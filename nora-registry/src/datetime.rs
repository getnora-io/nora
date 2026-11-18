// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Every date NORA writes or reads, in one place (#1282).
//!
//! The spellings are the ones NORA has always produced and accepted; stores written by earlier
//! releases are read back the same way, and clients see the same bytes. The golden tests below
//! pin each spelling and each parser to literal values.

use std::fmt;

/// An instant in UTC, to the nanosecond.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTime {
    secs: i64,
    nanos: u32,
}

impl UtcTime {
    /// 1970-01-01T00:00:00Z.
    pub const EPOCH: UtcTime = UtcTime { secs: 0, nanos: 0 };

    /// Now, by the system clock.
    pub fn now() -> UtcTime {
        imp::now()
    }

    /// The instant `secs` seconds and `nanos` nanoseconds after the epoch, if it is within the
    /// representable range (years -262143..=262142) and `nanos` is under a second — or under
    /// two at the last second of a minute, a leap second (`23:59:60`).
    pub fn from_unix(secs: i64, nanos: u32) -> Option<UtcTime> {
        imp::checked(secs, nanos)
    }

    /// Whole seconds since the epoch (rounded down).
    pub fn unix(self) -> i64 {
        self.secs
    }

    /// Nanoseconds past [`UtcTime::unix`].
    pub fn subsec_nanos(self) -> u32 {
        self.nanos
    }

    /// RFC 3339 with `Z` and as many fraction digits as the value needs, in groups of three:
    /// `2026-11-17T08:15:00Z`, `2026-11-17T08:15:00.120Z`, `2026-11-17T08:15:00.123456789Z`.
    /// The JSON form of every serialized time (audit log, activity, backup metadata).
    pub fn rfc3339(self) -> String {
        imp::rfc3339(self, true)
    }

    /// RFC 3339 to the second, with `Z`: `2026-11-17T08:15:00Z` (Docker token `issued_at`).
    pub fn rfc3339_secs(self) -> String {
        imp::rfc3339(self, false)
    }

    /// HTTP-date (RFC 9110 IMF-fixdate): `Tue, 17 Nov 2026 08:15:00 GMT`.
    pub fn http_date(self) -> String {
        imp::strftime(self, "%a, %d %b %Y %H:%M:%S GMT")
    }

    /// The `Date:` of an apt `Release` file: `Tue, 17 Nov 2026 08:15:00 UTC`.
    pub fn apt_release_date(self) -> String {
        imp::strftime(self, "%a, %d %b %Y %H:%M:%S UTC")
    }

    /// Maven `lastUpdated`: `20261117081500`.
    pub fn maven_last_updated(self) -> String {
        imp::strftime(self, "%Y%m%d%H%M%S")
    }

    /// Composer `time` of a published version: `2026-11-17T08:15:00+00:00`.
    pub fn composer_time(self) -> String {
        imp::strftime(self, "%Y-%m-%dT%H:%M:%S+00:00")
    }

    /// Whole seconds from `self` to `later` (negative when `later` is earlier).
    pub fn seconds_until(self, later: UtcTime) -> i64 {
        imp::seconds_between(self, later)
    }
}

/// `2026-11-17 08:15:00.123456789 UTC`, as `backup restore` prints the backup's creation time.
impl fmt::Display for UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&imp::display(*self))
    }
}

impl serde::Serialize for UtcTime {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.rfc3339())
    }
}

impl<'de> serde::Deserialize<'de> for UtcTime {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        parse_rfc3339_relaxed(&s).ok_or_else(|| {
            serde::de::Error::custom(format!("not an RFC 3339 date and time: {s:?}"))
        })
    }
}

/// Seconds since the epoch, now.
pub fn now_unix() -> i64 {
    UtcTime::now().unix()
}

/// Now less `secs` seconds, to the second: the release date tests give a fixture.
#[cfg(test)]
pub fn ago(secs: i64) -> UtcTime {
    UtcTime::from_unix(now_unix() - secs, 0).expect("a test date is in range")
}

/// A serialized time read back: RFC 3339 with the leniency NORA has always had (`t` or a space
/// for `T`, `UTC` or an offset for `Z`, spaces around the fields). Converted to UTC.
pub fn parse_rfc3339_relaxed(s: &str) -> Option<UtcTime> {
    imp::parse_rfc3339_relaxed(s)
}

/// Parse an ISO 8601 / RFC 3339 date string to a Unix timestamp (seconds).
///
/// Handles common formats from registry metadata:
/// - `2024-01-15T10:30:00Z` (Go .info `Time` field)
/// - `2024-01-15T10:30:00.123Z` (npm `time` field)
/// - `2024-01-15T10:30:00+00:00` (PyPI `upload_time_iso_8601`)
/// - `2024-01-15T10:30:00.000+0000` (Conan `time` field — non-standard tz offset)
/// - `2024-01-15T10:30:00` (no zone: UTC)
///
/// Returns `None` if the string is not parseable.
pub fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    imp::parse_iso8601_to_unix(s)
}

/// An RFC 2822 date (an upstream's `Last-Modified`) as seconds since the epoch.
pub fn parse_rfc2822_to_unix(s: &str) -> Option<i64> {
    imp::parse_rfc2822_to_unix(s)
}

mod imp {
    use super::UtcTime;
    use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat, Utc};

    fn chrono(t: UtcTime) -> DateTime<Utc> {
        DateTime::from_timestamp(t.secs, t.nanos).expect("UtcTime is always in range")
    }

    fn of(dt: DateTime<Utc>) -> UtcTime {
        UtcTime {
            secs: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos(),
        }
    }

    pub(super) fn now() -> UtcTime {
        of(Utc::now())
    }

    pub(super) fn checked(secs: i64, nanos: u32) -> Option<UtcTime> {
        DateTime::from_timestamp(secs, nanos).map(of)
    }

    pub(super) fn rfc3339(t: UtcTime, auto: bool) -> String {
        let form = if auto {
            SecondsFormat::AutoSi
        } else {
            SecondsFormat::Secs
        };
        chrono(t).to_rfc3339_opts(form, true)
    }

    pub(super) fn strftime(t: UtcTime, format: &str) -> String {
        chrono(t).format(format).to_string()
    }

    pub(super) fn display(t: UtcTime) -> String {
        chrono(t).to_string()
    }

    pub(super) fn seconds_between(a: UtcTime, b: UtcTime) -> i64 {
        chrono(b).signed_duration_since(chrono(a)).num_seconds()
    }

    pub(super) fn parse_rfc3339_relaxed(s: &str) -> Option<UtcTime> {
        s.parse::<DateTime<FixedOffset>>()
            .ok()
            .map(|dt| of(dt.with_timezone(&Utc)))
    }

    pub(super) fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
        // Try RFC 3339 / ISO 8601 with timezone
        if let Ok(dt) = DateTime::<FixedOffset>::parse_from_rfc3339(s) {
            return Some(dt.timestamp());
        }

        // Try without timezone (assume UTC) — some registries omit the Z
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
            return Some(ndt.and_utc().timestamp());
        }
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
            return Some(ndt.and_utc().timestamp());
        }

        // Try non-standard offset format without colon: +0000, +0530
        // (Conan center uses this format)
        if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f%z") {
            return Some(dt.timestamp());
        }
        if let Ok(dt) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%z") {
            return Some(dt.timestamp());
        }

        None
    }

    pub(super) fn parse_rfc2822_to_unix(s: &str) -> Option<i64> {
        DateTime::parse_from_rfc2822(s).ok().map(|d| d.timestamp())
    }
}

#[cfg(test)]
#[path = "datetime_golden.rs"]
mod golden;
