// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};
use std::path::Path;

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

/// Accepted pairs remembered at most; past it that memory starts over. Only a valid password
/// adds to it, so refusals never push an accepted pair out.
const ACCEPTED_CAPACITY: usize = 4096;

/// Refused pairs remembered at most; past it that memory starts over, the accepted pairs kept.
const REFUSED_CAPACITY: usize = 4096;

/// Htpasswd-based authentication.
///
/// bcrypt is slow on purpose, so it never runs on an async worker: checks run on the
/// blocking pool, a few at a time, and each verdict is remembered. The file is read once at
/// startup, so a username and password get the same answer for the life of the process;
/// the second request with them (a CI job's next pull, an API token sent as the password of
/// an htpasswd username) pays no bcrypt. Accepted and refused pairs are remembered apart, so a
/// flood of wrong passwords cannot make an accepted pair pay bcrypt again: an accepted pair
/// pays it once while it is among the [`ACCEPTED_CAPACITY`] remembered.
pub struct HtpasswdAuth {
    users: HashMap<String, String>, // username -> bcrypt hash
    /// Pairs bcrypt accepted, by a keyed digest of username and password, never the password
    /// itself. Read on every request, written only after a bcrypt check.
    accepted: ArcSwap<HashSet<[u8; 32]>>,
    /// Pairs bcrypt refused, keyed the same way.
    refused: ArcSwap<HashSet<[u8; 32]>>,
    /// Pairs remembered at most in each: [`ACCEPTED_CAPACITY`] and [`REFUSED_CAPACITY`], and
    /// less in tests.
    capacity: Capacity,
    /// Key of those digests, random per process.
    key: [u8; 32],
    /// bcrypt checks running at once at most: half the cores, so a flood of logins leaves
    /// the rest of the CPU to the requests.
    checks: Semaphore,
    /// bcrypt verifications run, for tests that prove a path runs none.
    #[cfg(test)]
    pub(crate) bcrypt_runs: std::sync::atomic::AtomicUsize,
}

/// How many accepted and refused pairs [`HtpasswdAuth`] remembers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Capacity {
    accepted: usize,
    refused: usize,
}

impl HtpasswdAuth {
    /// Load users from htpasswd file
    pub fn from_file(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        let mut users = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((username, hash)) = line.split_once(':') {
                users.insert(username.to_string(), hash.to_string());
            }
        }

        let mut unreadable: Vec<&str> = users
            .iter()
            .filter(|(_, hash)| !bcrypt_can_read(hash))
            .map(|(username, _)| username.as_str())
            .collect();
        if !unreadable.is_empty() {
            unreadable.sort_unstable();
            // The names only: a hash is a secret too.
            tracing::warn!(
                file = %path.display(),
                users = ?unreadable,
                "htpasswd lines whose hash is not bcrypt never match a password: \
                 rewrite them with `htpasswd -B`"
            );
        }

        if users.is_empty() {
            None
        } else {
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
            Some(Self {
                users,
                accepted: ArcSwap::default(),
                refused: ArcSwap::default(),
                capacity: Capacity {
                    accepted: ACCEPTED_CAPACITY,
                    refused: REFUSED_CAPACITY,
                },
                key: rand::random(),
                checks: Semaphore::new((cores / 2).max(1)),
                #[cfg(test)]
                bcrypt_runs: Default::default(),
            })
        }
    }

    /// Whether `password` is `username`'s. bcrypt runs, on the blocking pool, only for a
    /// known user whose verdict is not remembered yet.
    pub async fn verify(&self, username: &str, password: &str) -> bool {
        let Some(hash) = self.users.get(username) else {
            return false;
        };
        let key = self.verdict_key(username, password);
        if let Some(verdict) = self.remembered(&key) {
            return verdict;
        }
        let Ok(_permit) = self.checks.acquire().await else {
            return false;
        };
        // Another request may have checked the same pair while this one waited.
        if let Some(verdict) = self.remembered(&key) {
            return verdict;
        }
        #[cfg(test)]
        self.bcrypt_runs
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (hash, password) = (hash.clone(), Zeroizing::new(password.to_owned()));
        match tokio::task::spawn_blocking(move || bcrypt::verify(password.as_str(), &hash)).await {
            Ok(checked) => {
                // A hash bcrypt cannot read matches nothing, now or later.
                let verdict = checked.unwrap_or(false);
                self.remember(key, verdict);
                verdict
            }
            // The check panicked: refuse, and check again next time.
            Err(_) => false,
        }
    }

    /// The verdict for `username` and `password` without running bcrypt: `Some(false)` for
    /// an unknown user, `None` when the pair has not been checked yet.
    pub fn verified(&self, username: &str, password: &str) -> Option<bool> {
        if !self.users.contains_key(username) {
            return Some(false);
        }
        self.remembered(&self.verdict_key(username, password))
    }

    fn verdict_key(&self, username: &str, password: &str) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(self.key);
        // The length first, so no other username and password make the same bytes.
        digest.update((username.len() as u64).to_le_bytes());
        digest.update(username.as_bytes());
        digest.update(password.as_bytes());
        digest.finalize().into()
    }

    fn remembered(&self, key: &[u8; 32]) -> Option<bool> {
        if self.accepted.load().contains(key) {
            Some(true)
        } else if self.refused.load().contains(key) {
            Some(false)
        } else {
            None
        }
    }

    fn remember(&self, key: [u8; 32], verdict: bool) {
        let (pairs, capacity) = if verdict {
            (&self.accepted, self.capacity.accepted)
        } else {
            (&self.refused, self.capacity.refused)
        };
        pairs.rcu(|pairs| {
            let mut next = if pairs.len() >= capacity {
                HashSet::new()
            } else {
                HashSet::clone(pairs)
            };
            next.insert(key);
            next
        });
    }

    /// Get list of usernames
    pub fn list_users(&self) -> Vec<&str> {
        self.users.keys().map(|s| s.as_str()).collect()
    }
}

/// Whether `hash` has bcrypt's form, `$2a$`, `$2b$`, `$2x$` or `$2y$`, a cost bcrypt accepts
/// and 53 characters of its alphabet: the only hashes [`HtpasswdAuth::verify`] can match.
fn bcrypt_can_read(hash: &str) -> bool {
    let bytes = hash.as_bytes();
    bytes.len() == 60
        && hash.is_ascii()
        && matches!(&hash[..4], "$2a$" | "$2b$" | "$2x$" | "$2y$")
        && hash[4..6]
            .parse::<u32>()
            .is_ok_and(|cost| (4..=31).contains(&cost))
        && bytes[6] == b'$'
        && bytes[7..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Lines htpasswd writes with other schemes (`-s`, `-m`, `-d`, `-p`), an empty hash, and
    /// a bcrypt one with a cost bcrypt refuses.
    const UNREADABLE: [(&str, &str); 6] = [
        ("sha", "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="),
        ("apr1", "$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/"),
        ("crypt", "rqXexS6ZhobKA"),
        ("plain", "plaintext-secret"),
        ("empty", ""),
        (
            "cost3",
            "$2y$03$KjmTqvC8hRzE5SXXRomtA.dEqMtHvC6Fq7S6eRjsnTF0q4pFRGn2a",
        ),
    ];

    fn create_test_htpasswd(entries: &[(&str, &str)]) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        for (username, password) in entries {
            let hash = bcrypt::hash(password, 4).unwrap(); // cost=4 for speed in tests
            writeln!(file, "{}:{}", username, hash).unwrap();
        }
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_htpasswd_loading() {
        let file = create_test_htpasswd(&[("admin", "secret"), ("user", "password")]);

        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        let users = auth.list_users();
        assert_eq!(users.len(), 2);
        assert!(users.contains(&"admin"));
        assert!(users.contains(&"user"));
    }

    #[test]
    fn test_htpasswd_loading_empty_file() {
        let file = NamedTempFile::new().unwrap();
        let auth = HtpasswdAuth::from_file(file.path());
        assert!(auth.is_none());
    }

    #[test]
    fn test_htpasswd_loading_with_comments() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file).unwrap();
        let hash = bcrypt::hash("secret", 4).unwrap();
        writeln!(file, "admin:{}", hash).unwrap();
        file.flush().unwrap();

        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        assert_eq!(auth.list_users().len(), 1);
    }

    #[tokio::test]
    async fn test_authenticate_valid() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(auth.verify("test", "secret").await);
    }

    #[tokio::test]
    async fn test_authenticate_invalid_password() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(!auth.verify("test", "wrong").await);
    }

    #[tokio::test]
    async fn test_authenticate_unknown_user() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(!auth.verify("unknown", "secret").await);
        assert_eq!(
            auth.bcrypt_runs.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    /// A remembered verdict is the verdict bcrypt gave, right or wrong, and is told apart
    /// per username and password; `verified` reports only what was checked.
    #[tokio::test]
    async fn a_remembered_verdict_is_the_checked_one() {
        let file = create_test_htpasswd(&[("a", "pw-a"), ("b", "pw-b")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        assert_eq!(auth.verified("a", "pw-a"), None);
        assert_eq!(auth.verified("nobody", "pw-a"), Some(false));
        for _ in 0..3 {
            assert!(auth.verify("a", "pw-a").await);
            assert!(!auth.verify("a", "pw-b").await);
            assert!(!auth.verify("b", "pw-a").await);
            assert!(auth.verify("b", "pw-b").await);
        }
        assert_eq!(
            auth.bcrypt_runs.load(std::sync::atomic::Ordering::SeqCst),
            4
        );
        assert_eq!(auth.verified("a", "pw-a"), Some(true));
        assert_eq!(auth.verified("a", "pw-b"), Some(false));
    }

    /// A hash bcrypt cannot read refuses every password, every time: a line htpasswd wrote
    /// with another scheme (`-s`, `-m`, `-d`, `-p`), an empty one, a bcrypt one with a cost
    /// out of range. Remembered as a refusal, never as a match.
    #[tokio::test]
    async fn a_hash_bcrypt_cannot_read_matches_no_password() {
        let mut file = NamedTempFile::new().unwrap();
        for (user, hash) in UNREADABLE {
            writeln!(file, "{user}:{hash}").unwrap();
        }
        file.flush().unwrap();
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        for (user, hash) in UNREADABLE {
            assert!(bcrypt::verify("password", hash).is_err(), "{user}");
            for password in ["password", "", hash, "anything"] {
                for _ in 0..2 {
                    assert!(!auth.verify(user, password).await, "{user}: {password}");
                }
                assert_eq!(auth.verified(user, password), Some(false), "{user}");
            }
        }
    }

    /// Each kind of line that can never match is told apart from a bcrypt hash, the same way
    /// bcrypt itself tells them apart.
    #[test]
    fn only_a_bcrypt_hash_is_readable() {
        let bcrypt_hash = bcrypt::hash("pw", 4).unwrap();
        for hash in [
            bcrypt_hash.as_str(),
            &bcrypt_hash.replacen("$2b$", "$2y$", 1),
            &bcrypt_hash.replacen("$2b$", "$2a$", 1),
        ] {
            assert!(bcrypt_can_read(hash), "{hash}");
            assert!(bcrypt::verify("pw", hash).unwrap(), "{hash}");
        }
        for hash in UNREADABLE.map(|(_, hash)| hash) {
            assert!(!bcrypt_can_read(hash), "{hash}");
            assert!(bcrypt::verify("password", hash).is_err(), "{hash}");
        }
    }

    /// Loading a file with lines that can never match warns once, naming their users and
    /// not their hashes; a file of bcrypt lines loads without it.
    #[test]
    fn lines_that_can_never_match_are_named_at_load() {
        use tracing_subscriber::fmt::MakeWriter;
        #[derive(Clone, Default)]
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Captured {
            type Writer = Captured;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }
        let load = |file: &NamedTempFile| {
            let sink = Captured::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(sink.clone())
                .with_ansi(false)
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                HtpasswdAuth::from_file(file.path()).unwrap();
            });
            let bytes = sink.0.lock().unwrap().clone();
            String::from_utf8(bytes).unwrap()
        };

        let mut file = create_test_htpasswd(&[("good", "pw")]);
        assert_eq!(load(&file), "");
        for (user, hash) in UNREADABLE {
            writeln!(file, "{user}:{hash}").unwrap();
        }
        file.flush().unwrap();
        let log = load(&file);
        assert_eq!(log.lines().count(), 1, "{log}");
        assert!(log.contains("WARN"), "{log}");
        for (user, hash) in UNREADABLE {
            assert!(log.contains(&format!("\"{user}\"")), "{user}: {log}");
            if !hash.is_empty() {
                assert!(!log.contains(hash), "{user}'s hash: {log}");
            }
        }
        assert!(!log.contains("\"good\""), "{log}");
    }

    /// Check every pair at once, as a flood of requests would.
    async fn verify_all(auth: &HtpasswdAuth, pairs: &[(String, String)]) -> Vec<bool> {
        use futures::StreamExt;
        futures::stream::iter(pairs)
            .map(|(user, password)| auth.verify(user, password))
            .buffered(16)
            .collect()
            .await
    }

    fn runs(auth: &HtpasswdAuth) -> usize {
        auth.bcrypt_runs.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The server remembers at least 4096 accepted and 4096 refused pairs, the numbers the
    /// type's documentation and the authentication guarantee name.
    #[test]
    fn the_server_remembers_at_least_4096_accepted_and_4096_refused_pairs() {
        let file = create_test_htpasswd(&[("a", "pw")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        assert!(auth.capacity.accepted >= 4096, "{:?}", auth.capacity);
        assert!(auth.capacity.refused >= 4096, "{:?}", auth.capacity);
    }

    /// At the server's capacities: refusals past the number remembered, cheap ones from a
    /// user whose hash bcrypt cannot read, leave an accepted pair remembered.
    #[tokio::test]
    async fn refusals_past_the_server_capacity_keep_an_accepted_pair_remembered() {
        let mut file = create_test_htpasswd(&[("a", "pw")]);
        writeln!(file, "z:{{SHA}}W6ph5Mm5Pz8GgiULbPgzG37mj9g=").unwrap();
        file.flush().unwrap();
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        assert!(auth.verify("a", "pw").await);
        let refused: Vec<_> = (0..=auth.capacity.refused)
            .map(|i| ("z".to_owned(), format!("guess{i}")))
            .collect();
        assert!(verify_all(&auth, &refused).await.iter().all(|ok| !ok));
        let before = runs(&auth);
        assert_eq!(auth.verified("a", "pw"), Some(true));
        assert!(auth.verify("a", "pw").await);
        assert_eq!(runs(&auth), before, "an accepted pair pays bcrypt again");
    }

    /// A flood of wrong passwords, more than the refusals remembered, does not make a pair
    /// already accepted pay bcrypt again; up to the capacity every refusal is remembered too.
    #[tokio::test]
    async fn a_flood_of_wrong_passwords_keeps_an_accepted_pair_remembered() {
        let file = create_test_htpasswd(&[("a", "pw")]);
        let mut auth = HtpasswdAuth::from_file(file.path()).unwrap();
        auth.capacity = Capacity {
            accepted: 8,
            refused: 8,
        };
        assert!(auth.verify("a", "pw").await);
        let wrong: Vec<_> = (0..8)
            .map(|i| ("a".to_owned(), format!("wrong{i}")))
            .collect();
        assert!(verify_all(&auth, &wrong).await.iter().all(|ok| !ok));
        for (user, password) in &wrong {
            assert_eq!(auth.verified(user, password), Some(false), "{password}");
        }
        let flood: Vec<_> = (0..100)
            .map(|i| ("a".to_owned(), format!("flood{i}")))
            .collect();
        assert!(verify_all(&auth, &flood).await.iter().all(|ok| !ok));
        let before = runs(&auth);
        assert_eq!(auth.verified("a", "pw"), Some(true));
        assert!(auth.verify("a", "pw").await);
        assert_eq!(runs(&auth), before, "an accepted pair pays bcrypt again");
    }

    /// As many accepted pairs as the capacity are all remembered: none pays bcrypt twice.
    /// One past it, that memory starts over.
    #[tokio::test]
    async fn accepted_pairs_up_to_the_capacity_pay_bcrypt_once() {
        let hash = bcrypt::hash("pw", 4).unwrap();
        let mut file = NamedTempFile::new().unwrap();
        for i in 0..9 {
            writeln!(file, "u{i}:{hash}").unwrap();
        }
        file.flush().unwrap();
        let mut auth = HtpasswdAuth::from_file(file.path()).unwrap();
        auth.capacity = Capacity {
            accepted: 8,
            refused: 8,
        };
        let pairs: Vec<_> = (0..8).map(|i| (format!("u{i}"), "pw".to_owned())).collect();
        assert!(verify_all(&auth, &pairs).await.iter().all(|ok| *ok));
        assert_eq!(runs(&auth), 8);
        for (user, password) in &pairs {
            assert_eq!(auth.verified(user, password), Some(true), "{user}");
        }
        assert!(verify_all(&auth, &pairs).await.iter().all(|ok| *ok));
        assert_eq!(runs(&auth), 8);
        assert!(auth.verify("u8", "pw").await);
        assert_eq!(
            auth.verified("u0", "pw"),
            None,
            "past the capacity it starts over"
        );
    }

    /// One username and password make one key; moving bytes across the boundary between
    /// them makes another.
    #[test]
    fn the_verdict_key_keeps_username_and_password_apart() {
        let file = create_test_htpasswd(&[("a", "pw")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();
        assert_eq!(auth.verdict_key("a", "bpw"), auth.verdict_key("a", "bpw"));
        assert_ne!(auth.verdict_key("a", "bpw"), auth.verdict_key("ab", "pw"));
        assert_ne!(auth.verdict_key("a\0b", "c"), auth.verdict_key("a", "b\0c"));
    }
}
