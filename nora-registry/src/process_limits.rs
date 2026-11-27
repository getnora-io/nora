// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! The open-file limit the process runs with (#1321).
//!
//! A container inherits the soft `RLIMIT_NOFILE` of its runtime: 1024 on a default Docker or
//! Kubernetes node, while the hard limit there is usually 524288 or more. Every client
//! connection and every open file takes a descriptor, so with 1024 NORA stopped accepting
//! connections at about a thousand requests in flight. Go and the JVM raise the soft limit to
//! the hard one when a program starts; NORA does the same, in `main`, before the async runtime
//! opens its first descriptor.
//!
//! Linux only: release builds are Linux, and other kernels cap the value below what the limit
//! reports. The limits are read from `/proc/self/limits`, a read that can fail, and not with
//! `getrlimit`, which rustix treats as a call that cannot fail. Only the soft limit moves, only
//! up, and only to the hard limit the process already has; an operator who wants a lower
//! ceiling sets the hard limit (`--ulimit nofile=N:N`, `LimitNOFILE=N`).

/// A limit as the kernel reports it; `None` is "unlimited".
pub type Limit = Option<u64>;

/// The soft and hard `RLIMIT_NOFILE` of the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFiles {
    pub soft: Limit,
    pub hard: Limit,
}

/// What became of the limit at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The soft limit already was the hard one, or one of them is unlimited.
    Unchanged(OpenFiles),
    /// The soft limit was raised; `after` is read back from the kernel.
    Raised { before: OpenFiles, after: OpenFiles },
    /// The kernel refused the raise (a seccomp profile, for one); the limit is as it was.
    Refused { before: OpenFiles, error: String },
    /// `/proc/self/limits` could not be read or parsed; nothing was changed.
    Unreadable(String),
    /// Not Linux: nothing is read or changed.
    NotApplicable,
}

impl Outcome {
    /// The soft limit the process runs with, when known.
    pub fn soft(&self) -> Limit {
        match self {
            Outcome::Unchanged(now) => now.soft,
            Outcome::Raised { after, .. } => after.soft,
            Outcome::Refused { before, .. } => before.soft,
            Outcome::Unreadable(_) | Outcome::NotApplicable => None,
        }
    }
}

/// The soft limit to set for `now`, if it should move: to the hard limit, never down, and not
/// when either is unlimited (nothing to raise to, or nothing to gain).
pub fn raise_to(now: OpenFiles) -> Option<u64> {
    match (now.soft, now.hard) {
        (Some(soft), Some(hard)) if soft < hard => Some(hard),
        _ => None,
    }
}

/// The `Max open files` line of `/proc/<pid>/limits`.
pub fn parse_limits(text: &str) -> Option<OpenFiles> {
    let rest = text
        .lines()
        .find_map(|l| l.strip_prefix("Max open files"))?;
    let mut fields = rest.split_whitespace();
    let soft = parse_limit(fields.next()?)?;
    let hard = parse_limit(fields.next()?)?;
    Some(OpenFiles { soft, hard })
}

fn parse_limit(field: &str) -> Option<Limit> {
    if field == "unlimited" {
        Some(None)
    } else {
        field.parse().ok().map(Some)
    }
}

/// How many descriptors NORA needs besides its connections: files it streams, the store's
/// own handles, log and audit files, the upstream connections.
pub const FILE_RESERVE: u64 = 1024;

/// Whether `soft` leaves fewer descriptors than `max_connections` connections and the reserve
/// need: past that, connections are refused although NORA would still accept them.
pub fn below_connection_budget(soft: Limit, max_connections: usize) -> bool {
    match soft {
        Some(soft) => soft < (max_connections as u64).saturating_add(FILE_RESERVE),
        None => false,
    }
}

/// Raise the soft open-file limit of this process to its hard limit. Called once, from `main`,
/// before the async runtime starts.
pub fn raise_open_files() -> Outcome {
    if cfg!(target_os = "linux") {
        imp::raise_open_files()
    } else {
        Outcome::NotApplicable
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{parse_limits, raise_to, OpenFiles, Outcome};
    use rustix::process::{setrlimit, Resource, Rlimit};

    /// Why `/proc/self/limits` gave no limit.
    #[derive(Debug, thiserror::Error)]
    enum ReadError {
        #[error("{0}")]
        Io(#[from] std::io::Error),
        #[error("no \"Max open files\" line")]
        NoLine,
    }

    fn read() -> Result<OpenFiles, ReadError> {
        let text = std::fs::read_to_string("/proc/self/limits")?;
        parse_limits(&text).ok_or(ReadError::NoLine)
    }

    pub(super) fn raise_open_files() -> Outcome {
        let before = match read() {
            Ok(now) => now,
            Err(error) => return Outcome::Unreadable(error.to_string()),
        };
        let Some(to) = raise_to(before) else {
            return Outcome::Unchanged(before);
        };
        // The hard limit is written back as read. A supervisor that changed the limits of this
        // process between the read and this write would see them reset; supervisors set limits
        // before exec, and the value is read back below and logged.
        let new = Rlimit {
            current: Some(to),
            maximum: before.hard,
        };
        if let Err(e) = setrlimit(Resource::Nofile, new) {
            return Outcome::Refused {
                before,
                error: e.to_string(),
            };
        }
        match read() {
            Ok(after) => Outcome::Raised { before, after },
            // Set, but not readable back: the value written is what the kernel accepted.
            Err(_) => Outcome::Raised {
                before,
                after: OpenFiles {
                    soft: Some(to),
                    hard: before.hard,
                },
            },
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::Outcome;

    pub(super) fn raise_open_files() -> Outcome {
        Outcome::NotApplicable
    }
}

/// The line written to stderr before the runtime starts when the raise did not happen: with a
/// very low limit the runtime itself may fail to start, and the log would never say why.
pub fn early_notice(outcome: &Outcome) -> Option<String> {
    match outcome {
        Outcome::Refused { before, error } => Some(format!(
            "nora: open files: the soft limit {:?} could not be raised to the hard limit {:?}: {error}",
            before.soft, before.hard
        )),
        Outcome::Unreadable(error) => Some(format!(
            "nora: open files: the limit could not be read ({error}), left as it is"
        )),
        _ => None,
    }
}

/// Write the outcome to the log, next to the connection limits it bounds (server only: a CLI
/// command's stdout may be machine-read).
pub fn log_outcome(outcome: &Outcome, max_connections: usize) {
    match outcome {
        Outcome::Raised { before, after } => tracing::info!(
            soft_before = ?before.soft,
            soft = ?after.soft,
            hard = ?after.hard,
            "Open files: soft limit raised to the hard limit"
        ),
        Outcome::Unchanged(now) => {
            tracing::info!(soft = ?now.soft, hard = ?now.hard, "Open files limit")
        }
        Outcome::Refused { before, error } => tracing::warn!(
            soft = ?before.soft,
            hard = ?before.hard,
            error = %error,
            "Open files: the soft limit could not be raised to the hard limit"
        ),
        Outcome::Unreadable(error) => tracing::warn!(
            error = %error,
            "Open files: the limit could not be read, left as it is"
        ),
        Outcome::NotApplicable => {}
    }
    if below_connection_budget(outcome.soft(), max_connections) {
        tracing::warn!(
            soft = ?outcome.soft(),
            max_connections,
            reserve = FILE_RESERVE,
            "Open files: the limit is below max_connections plus a reserve for files, so connections \
             past it are refused; raise the hard limit (docker run --ulimit nofile=1048576, \
             systemd LimitNOFILE=1048576)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCKER: &str =
        "Limit                     Soft Limit           Hard Limit           Units     \n\
Max cpu time              unlimited            unlimited            seconds   \n\
Max open files            1024                 524288               files     \n\
Max locked memory         8388608              8388608              bytes     \n";

    fn pair(soft: Limit, hard: Limit) -> OpenFiles {
        OpenFiles { soft, hard }
    }

    #[test]
    fn the_open_files_line_is_read_from_proc_limits() {
        assert_eq!(parse_limits(DOCKER), Some(pair(Some(1024), Some(524288))));
        let unlimited = DOCKER.replace(
            "1024                 524288",
            "unlimited            unlimited",
        );
        assert_eq!(parse_limits(&unlimited), Some(pair(None, None)));
        assert_eq!(
            parse_limits("Max cpu time unlimited unlimited seconds\n"),
            None
        );
        assert_eq!(parse_limits("Max open files  many  524288  files\n"), None);
        assert_eq!(parse_limits("Max open files  1024\n"), None);
    }

    #[test]
    fn the_soft_limit_moves_only_up_to_the_hard_one() {
        // A default Docker container, a systemd unit with LimitNOFILE=65535, a hard ceiling an
        // operator set equal to the soft one, unlimited either side, and a soft limit above a
        // hard one, which the kernel does not allow but a bad read could report.
        assert_eq!(raise_to(pair(Some(1024), Some(524288))), Some(524288));
        assert_eq!(raise_to(pair(Some(65535), Some(65535))), None);
        assert_eq!(raise_to(pair(Some(4096), Some(4096))), None);
        assert_eq!(raise_to(pair(None, None)), None);
        assert_eq!(raise_to(pair(Some(1024), None)), None);
        assert_eq!(raise_to(pair(None, Some(1024))), None);
        assert_eq!(raise_to(pair(Some(2048), Some(1024))), None);
    }

    #[test]
    fn the_warning_compares_the_limit_with_the_connections_and_a_reserve() {
        // The default max_connections is 4096.
        assert!(below_connection_budget(Some(1024), 4096));
        assert!(below_connection_budget(Some(4096), 4096));
        assert!(below_connection_budget(Some(5119), 4096));
        assert!(!below_connection_budget(Some(5120), 4096));
        assert!(!below_connection_budget(Some(524288), 4096));
        assert!(!below_connection_budget(None, 4096));
        assert!(below_connection_budget(Some(65535), 65535));
        assert!(!below_connection_budget(Some(u64::MAX), usize::MAX));
    }

    #[test]
    fn a_refused_or_unreadable_limit_is_said_before_the_runtime_starts() {
        let before = pair(Some(4), Some(4096));
        let refused = Outcome::Refused {
            before,
            error: "Operation not permitted".into(),
        };
        let line = early_notice(&refused).unwrap();
        assert!(
            line.contains("Some(4)") && line.contains("Operation not permitted"),
            "{line}"
        );
        assert!(early_notice(&Outcome::Unreadable("no /proc".into()))
            .unwrap()
            .contains("no /proc"));
        assert_eq!(early_notice(&Outcome::Unchanged(before)), None);
        assert_eq!(early_notice(&Outcome::NotApplicable), None);
    }

    #[test]
    fn the_soft_limit_the_process_reports() {
        let now = pair(Some(1024), Some(524288));
        let after = pair(Some(524288), Some(524288));
        assert_eq!(Outcome::Unchanged(now).soft(), Some(1024));
        assert_eq!(Outcome::Raised { before: now, after }.soft(), Some(524288));
        let refused = Outcome::Refused {
            before: now,
            error: "Operation not permitted".into(),
        };
        assert_eq!(refused.soft(), Some(1024));
        assert_eq!(Outcome::Unreadable("x".into()).soft(), None);
        assert_eq!(Outcome::NotApplicable.soft(), None);
    }

    /// The raise on this very process: it only ever raises, so it cannot disturb the tests
    /// running next to it.
    #[cfg(target_os = "linux")]
    #[test]
    fn after_the_raise_the_soft_limit_is_the_hard_one() {
        let outcome = raise_open_files();
        let now = parse_limits(&std::fs::read_to_string("/proc/self/limits").unwrap()).unwrap();
        if let Outcome::Refused { before, .. } = &outcome {
            // A sandbox (seccomp) may refuse the raise: then nothing moved.
            assert_eq!(&now, before, "{outcome:?}");
            return;
        }
        if let (Some(soft), Some(hard)) = (now.soft, now.hard) {
            assert_eq!(soft, hard, "{outcome:?}");
        }
        assert!(
            !matches!(outcome, Outcome::Unreadable(_) | Outcome::NotApplicable),
            "{outcome:?}"
        );
        assert_eq!(
            raise_open_files(),
            Outcome::Unchanged(now),
            "a second call changes nothing"
        );
    }
}
