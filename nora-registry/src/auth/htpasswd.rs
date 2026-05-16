// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::path::Path;

/// Htpasswd-based authentication
#[derive(Clone)]
pub struct HtpasswdAuth {
    users: HashMap<String, String>, // username -> bcrypt hash
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
            Some(Self { users })
        }
    }

    /// Verify username and password
    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        if let Some(hash) = self.users.get(username) {
            bcrypt::verify(password, hash).unwrap_or(false)
        } else {
            false
        }
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

    #[test]
    fn test_authenticate_valid() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(auth.authenticate("test", "secret"));
    }

    #[test]
    fn test_authenticate_invalid_password() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(!auth.authenticate("test", "wrong"));
    }

    #[test]
    fn test_authenticate_unknown_user() {
        let file = create_test_htpasswd(&[("test", "secret")]);
        let auth = HtpasswdAuth::from_file(file.path()).unwrap();

        assert!(!auth.authenticate("unknown", "secret"));
    }
}
