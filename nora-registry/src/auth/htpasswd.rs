// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::path::Path;

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

/// Verdicts remembered at most; past it the memory starts over.
const VERDICT_CAPACITY: usize = 4096;

/// Htpasswd-based authentication.
///
/// bcrypt is slow on purpose, so it never runs on an async worker: checks run on the
/// blocking pool, a few at a time, and each verdict is remembered. The file is read once at
/// startup, so a username and password get the same answer for the life of the process;
/// the second request with them (a CI job's next pull, an API token sent as the password of
/// an htpasswd username) pays no bcrypt.
pub struct HtpasswdAuth {
    users: HashMap<String, String>, // username -> bcrypt hash
    /// Verdicts by a keyed digest of username and password, never the password itself.
    /// Read on every request, written only after a bcrypt check.
    verdicts: ArcSwap<HashMap<[u8; 32], bool>>,
    /// Key of those digests, random per process.
    key: [u8; 32],
    /// bcrypt checks running at once at most: half the cores, so a flood of logins leaves
    /// the rest of the CPU to the requests.
    checks: Semaphore,
    /// bcrypt verifications run, for tests that prove a path runs none.
    #[cfg(test)]
    pub(crate) bcrypt_runs: std::sync::atomic::AtomicUsize,
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

        if users.is_empty() {
            None
        } else {
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
            Some(Self {
                users,
                verdicts: ArcSwap::default(),
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
        self.verdicts.load().get(key).copied()
    }

    fn remember(&self, key: [u8; 32], verdict: bool) {
        self.verdicts.rcu(|verdicts| {
            let mut next = if verdicts.len() >= VERDICT_CAPACITY {
                HashMap::new()
            } else {
                HashMap::clone(verdicts)
            };
            next.insert(key, verdict);
            next
        });
    }

    /// Get list of usernames
    pub fn list_users(&self) -> Vec<&str> {
        self.users.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

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
