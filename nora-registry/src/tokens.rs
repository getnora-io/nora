// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default TTL for cached token verifications (avoids Argon2 per request).
/// Overridable per-store via [`TokenStore::with_cache_ttl`] (config
/// `auth.token_cache_ttl`) to bound the cross-replica revocation window.
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Cached verification result
#[derive(Clone)]
struct CachedToken {
    user: String,
    role: Role,
    expires_at: u64,
    cached_at: Instant,
}

const TOKEN_PREFIX: &str = "nra_";

/// Access role for API tokens
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Role {
    Read,
    Write,
    Admin,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Read => write!(f, "read"),
            Role::Write => write!(f, "write"),
            Role::Admin => write!(f, "admin"),
        }
    }
}

impl Role {
    pub fn can_write(&self) -> bool {
        matches!(self, Role::Write | Role::Admin)
    }

    pub fn can_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

/// API Token metadata stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub token_hash: String,
    pub user: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used: Option<u64>,
    pub description: Option<String>,
    #[serde(default = "default_role")]
    pub role: Role,
}

fn default_role() -> Role {
    Role::Read
}

/// Token list entry for UI display (no hash exposed)
#[derive(Debug, Clone, Serialize)]
pub struct TokenListEntry {
    pub file_id: String,
    pub user: String,
    pub role: Role,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used: Option<u64>,
    pub description: Option<String>,
}

/// Token store for managing API tokens
#[derive(Clone)]
pub struct TokenStore {
    storage_path: PathBuf,
    /// In-memory cache: SHA256(token) -> verified result (avoids Argon2 per request)
    cache: Arc<RwLock<HashMap<String, CachedToken>>>,
    /// How long a cached verification is trusted before the slow path re-checks
    /// disk. Shorter = smaller cross-replica revocation window.
    cache_ttl: Duration,
    /// Pending last_used updates: file_id_prefix -> timestamp (flushed periodically)
    pending_last_used: Arc<RwLock<HashMap<String, u64>>>,
}

impl TokenStore {
    /// Create a new token store with the default verify-cache TTL.
    pub fn new(storage_path: &Path) -> Self {
        Self::with_cache_ttl(storage_path, DEFAULT_CACHE_TTL)
    }

    /// Create a token store with an explicit verify-cache TTL. A shorter TTL
    /// bounds the window in which a token revoked on another replica is still
    /// served from this replica's cache.
    pub fn with_cache_ttl(storage_path: &Path, cache_ttl: Duration) -> Self {
        // Ensure directory exists with restricted permissions. The serve path
        // fail-fasts on this in main.rs (#816); this is best-effort for library /
        // standalone use, but surface a diagnostic rather than swallowing the error
        // so a non-writable path is never silently broken until the first write.
        if let Err(e) = fs::create_dir_all(storage_path) {
            tracing::warn!(
                path = %storage_path.display(),
                error = %e,
                "TokenStore: could not create storage directory — token writes will fail"
            );
        }
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(storage_path, fs::Permissions::from_mode(0o700));
        }
        Self {
            storage_path: storage_path.to_path_buf(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
            pending_last_used: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new API token for a user
    pub fn create_token(
        &self,
        user: &str,
        ttl_days: u64,
        description: Option<String>,
        role: Role,
    ) -> Result<String, TokenError> {
        // Generate random token
        let raw_token = format!(
            "{}{}",
            TOKEN_PREFIX,
            Uuid::new_v4().to_string().replace("-", "")
        );
        let token_hash = hash_token_argon2(&raw_token)?;
        // Use SHA256 of token as filename (deterministic, for lookup)
        let file_id = sha256_hex(&raw_token);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = now + (ttl_days * 24 * 60 * 60);

        let info = TokenInfo {
            token_hash,
            user: user.to_string(),
            created_at: now,
            expires_at,
            last_used: None,
            description,
            role,
        };

        // Save to file with restricted permissions
        let file_path = self.storage_path.join(format!("{}.json", &file_id[..16]));
        let json =
            serde_json::to_string_pretty(&info).map_err(|e| TokenError::Storage(e.to_string()))?;
        fs::write(&file_path, &json).map_err(|e| TokenError::Storage(e.to_string()))?;
        set_file_permissions_600(&file_path);

        Ok(raw_token)
    }

    /// Verify a token and return user info if valid.
    ///
    /// Uses an in-memory cache to avoid Argon2 verification on every request.
    /// The `last_used` timestamp is updated in batch via `flush_last_used()`.
    pub fn verify_token(&self, token: &str) -> Result<(String, Role), TokenError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(TokenError::InvalidFormat);
        }

        let cache_key = sha256_hex(token);

        // Fast path: check in-memory cache
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&cache_key) {
                if cached.cached_at.elapsed() < self.cache_ttl {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now > cached.expires_at {
                        return Err(TokenError::Expired);
                    }
                    // Schedule deferred last_used update
                    self.pending_last_used
                        .write()
                        .insert(cache_key[..16].to_string(), now);
                    return Ok((cached.user.clone(), cached.role.clone()));
                }
            }
        }

        // Slow path: read from disk and verify Argon2
        let file_path = self.storage_path.join(format!("{}.json", &cache_key[..16]));

        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(TokenError::NotFound);
            }
            Err(e) => return Err(TokenError::Storage(e.to_string())),
        };

        let mut info: TokenInfo =
            serde_json::from_str(&content).map_err(|e| TokenError::Storage(e.to_string()))?;

        // Verify hash: try Argon2id first, fall back to legacy SHA256
        let hash_valid = if info.token_hash.starts_with("$argon2") {
            verify_token_argon2(token, &info.token_hash)
        } else {
            // Legacy SHA256 hash (no salt) — verify and migrate
            let legacy_hash = sha256_hex(token);
            if info.token_hash == legacy_hash {
                // Migrate to Argon2id
                if let Ok(new_hash) = hash_token_argon2(token) {
                    info.token_hash = new_hash;
                    if let Ok(json) = serde_json::to_string_pretty(&info) {
                        let _ = fs::write(&file_path, &json);
                        set_file_permissions_600(&file_path);
                    }
                }
                true
            } else {
                false
            }
        };

        if !hash_valid {
            return Err(TokenError::NotFound);
        }

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > info.expires_at {
            return Err(TokenError::Expired);
        }

        // Populate cache (key must match lookup at line 180: full 64-char SHA-256 hex)
        self.cache.write().insert(
            cache_key.clone(),
            CachedToken {
                user: info.user.clone(),
                role: info.role.clone(),
                expires_at: info.expires_at,
                cached_at: Instant::now(),
            },
        );

        // Schedule deferred last_used update
        self.pending_last_used
            .write()
            .insert(cache_key[..16].to_string(), now);

        Ok((info.user, info.role))
    }

    /// List all tokens for a user (returns TokenListEntry with file_id)
    pub fn list_tokens(&self, user: &str) -> Vec<TokenListEntry> {
        self.list_all_tokens()
            .into_iter()
            .filter(|t| t.user == user)
            .collect()
    }

    /// List all tokens across all users (for admin UI)
    pub fn list_all_tokens(&self) -> Vec<TokenListEntry> {
        let mut tokens = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.storage_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let file_id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if file_id.is_empty() {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(info) = serde_json::from_str::<TokenInfo>(&content) {
                        tokens.push(TokenListEntry {
                            file_id,
                            user: info.user,
                            role: info.role,
                            created_at: info.created_at,
                            expires_at: info.expires_at,
                            last_used: info.last_used,
                            description: info.description,
                        });
                    }
                }
            }
        }

        tokens.sort_by_key(|t| std::cmp::Reverse(t.created_at));
        tokens
    }

    /// Flush pending last_used timestamps to disk (async to avoid blocking runtime).
    /// Called periodically by background task (every 30s).
    pub async fn flush_last_used(&self) {
        let pending: HashMap<String, u64> = {
            let mut map = self.pending_last_used.write();
            std::mem::take(&mut *map)
        };

        if pending.is_empty() {
            return;
        }

        for (file_prefix, timestamp) in &pending {
            let file_path = self.storage_path.join(format!("{}.json", file_prefix));
            let content = match tokio::fs::read_to_string(&file_path).await {
                Ok(c) => c,
                Err(_) => continue,
            };
            let mut info: TokenInfo = match serde_json::from_str(&content) {
                Ok(i) => i,
                Err(_) => continue,
            };
            info.last_used = Some(*timestamp);
            if let Ok(json) = serde_json::to_string_pretty(&info) {
                let _ = tokio::fs::write(&file_path, &json).await;
                set_file_permissions_600(&file_path);
            }
        }

        tracing::debug!(count = pending.len(), "Flushed pending last_used updates");
    }

    /// Remove a token from the in-memory cache (called on revoke).
    /// Cache keys are full 64-char SHA-256 hex; revoke only knows the 16-char prefix,
    /// so we must scan for matching entries.
    fn invalidate_cache(&self, hash_prefix: &str) {
        self.cache
            .write()
            .retain(|k, _| !k.starts_with(hash_prefix));
    }

    /// Revoke a token by its hash prefix.
    ///
    /// `hash_prefix` must be exactly 16 lowercase hexadecimal characters (the
    /// first 16 chars of SHA-256(token)). Anything else is rejected to prevent
    /// path-traversal attacks via crafted prefixes like `../../etc/passwd`.
    pub fn revoke_token(&self, hash_prefix: &str) -> Result<(), TokenError> {
        // SECURITY: validate format before building filesystem path
        if !is_valid_hash_prefix(hash_prefix) {
            return Err(TokenError::NotFound);
        }
        let file_path = self.storage_path.join(format!("{}.json", hash_prefix));

        // TOCTOU fix: try remove directly
        match fs::remove_file(&file_path) {
            Ok(()) => {
                self.invalidate_cache(hash_prefix);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(TokenError::NotFound),
            Err(e) => Err(TokenError::Storage(e.to_string())),
        }
    }

    /// Revoke all tokens for a user
    pub fn revoke_all_for_user(&self, user: &str) -> usize {
        let mut count = 0;

        if let Ok(entries) = fs::read_dir(&self.storage_path) {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    if let Ok(info) = serde_json::from_str::<TokenInfo>(&content) {
                        if info.user == user && fs::remove_file(entry.path()).is_ok() {
                            count += 1;
                        }
                    }
                }
            }
        }

        // Evict cached entries for this user so revoked tokens fail immediately
        if count > 0 {
            self.cache.write().retain(|_, v| v.user != user);
        }

        count
    }
}

/// Validate a hash prefix: must be exactly 16 lowercase hex characters (`[0-9a-f]`).
///
/// Token files are named `{sha256(token)[..16]}.json` (always lowercase via
/// `hex::encode`). We restrict to lowercase only to prevent case-mismatch
/// issues on case-sensitive filesystems.
fn is_valid_hash_prefix(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Hash a token using Argon2id with random salt
fn hash_token_argon2(token: &str) -> Result<String, TokenError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(token.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| TokenError::Storage(format!("hash error: {e}")))
}

/// Verify a token against an Argon2id hash
fn verify_token_argon2(token: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(token.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// SHA256 hex digest (used for file naming and legacy hash verification)
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Set file permissions to 600 (owner read/write only)
fn set_file_permissions_600(path: &Path) {
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Invalid token format")]
    InvalidFormat,

    #[error("Token not found")]
    NotFound,

    #[error("Token expired")]
    Expired,

    #[error("Storage error: {0}")]
    Storage(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 30, Some("Test token".to_string()), Role::Write)
            .unwrap();

        assert!(token.starts_with("nra_"));
        assert_eq!(token.len(), 4 + 32); // prefix + uuid without dashes
    }

    /// The verify-cache TTL bounds the cross-replica revocation window. Two
    /// stores share one token dir (= two HA replicas, each with its own in-memory
    /// cache). A token revoked on replica A is still served from replica B's cache
    /// until B's `cache_ttl` elapses — and a short TTL bounds exactly that window.
    #[test]
    fn cache_ttl_bounds_cross_replica_revocation_window() {
        use std::thread::sleep;
        let dir = TempDir::new().unwrap();
        let replica_a = TokenStore::new(dir.path());
        let replica_b = TokenStore::with_cache_ttl(dir.path(), Duration::from_secs(1));

        let token = replica_a.create_token("u", 30, None, Role::Write).unwrap();

        // B verifies and caches the token.
        assert!(replica_b.verify_token(&token).is_ok());

        // A revokes it (removes the on-disk token + clears A's cache). B's cache is
        // untouched — there is no cross-pod invalidation.
        let hash_prefix = sha256_hex(&token)[..16].to_string();
        replica_a.revoke_token(&hash_prefix).unwrap();

        // WITHIN cache_ttl, B still serves the revoked token from cache — the
        // documented window.
        assert!(
            replica_b.verify_token(&token).is_ok(),
            "within cache_ttl, B serves from cache (bounded window)"
        );

        // After cache_ttl, B's entry is stale -> slow path re-reads disk -> the
        // revoked (deleted) token is rejected. The TTL bounds the window.
        sleep(Duration::from_millis(1100));
        assert!(
            matches!(replica_b.verify_token(&token), Err(TokenError::NotFound)),
            "after cache_ttl, B re-reads disk and rejects the revoked token"
        );
    }

    #[test]
    fn test_token_hash_is_argon2() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let _token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();

        let tokens = store.list_all_tokens();
        // Verify file_id is a hex prefix, not an Argon2 hash
        assert!(
            tokens[0].file_id.chars().all(|c| c.is_ascii_hexdigit()),
            "file_id must be hex, got: {}",
            tokens[0].file_id
        );
        assert_eq!(tokens[0].file_id.len(), 16);
    }

    #[test]
    fn test_verify_valid_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();
        let (user, role) = store.verify_token(&token).unwrap();

        assert_eq!(user, "testuser");
        assert_eq!(role, Role::Write);
    }

    #[test]
    fn test_verify_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let result = store.verify_token("invalid_token");
        assert!(matches!(result, Err(TokenError::InvalidFormat)));
    }

    #[test]
    fn test_verify_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let result = store.verify_token("nra_00000000000000000000000000000000");
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[test]
    fn test_verify_expired_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 1, None, Role::Write)
            .unwrap();
        let file_id = sha256_hex(&token);
        let file_path = temp_dir.path().join(format!("{}.json", &file_id[..16]));

        let content = std::fs::read_to_string(&file_path).unwrap();
        let mut info: TokenInfo = serde_json::from_str(&content).unwrap();
        info.expires_at = 0;
        std::fs::write(&file_path, serde_json::to_string(&info).unwrap()).unwrap();

        let result = store.verify_token(&token);
        assert!(matches!(result, Err(TokenError::Expired)));
    }

    #[test]
    fn test_legacy_sha256_migration() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        // Simulate a legacy token with SHA256 hash
        let raw_token = "nra_00112233445566778899aabbccddeeff";
        let legacy_hash = sha256_hex(raw_token);
        let file_id = sha256_hex(raw_token);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = TokenInfo {
            token_hash: legacy_hash.clone(),
            user: "legacyuser".to_string(),
            created_at: now,
            expires_at: now + 86400,
            last_used: None,
            description: None,
            role: Role::Read,
        };

        let file_path = temp_dir.path().join(format!("{}.json", &file_id[..16]));
        fs::write(&file_path, serde_json::to_string_pretty(&info).unwrap()).unwrap();

        // Verify should work with legacy hash
        let (user, role) = store.verify_token(raw_token).unwrap();
        assert_eq!(user, "legacyuser");
        assert_eq!(role, Role::Read);

        // After verification, hash should be migrated to Argon2id
        let content = fs::read_to_string(&file_path).unwrap();
        let updated: TokenInfo = serde_json::from_str(&content).unwrap();
        assert!(updated.token_hash.starts_with("$argon2"));
    }

    #[test]
    fn test_file_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();

        let file_id = sha256_hex(&token);
        let file_path = temp_dir.path().join(format!("{}.json", &file_id[..16]));

        #[cfg(unix)]
        {
            let metadata = fs::metadata(&file_path).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn test_list_tokens() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        store.create_token("user1", 30, None, Role::Write).unwrap();
        store.create_token("user1", 30, None, Role::Write).unwrap();
        store.create_token("user2", 30, None, Role::Read).unwrap();

        let user1_tokens = store.list_tokens("user1");
        assert_eq!(user1_tokens.len(), 2);

        let user2_tokens = store.list_tokens("user2");
        assert_eq!(user2_tokens.len(), 1);

        let unknown_tokens = store.list_tokens("unknown");
        assert_eq!(unknown_tokens.len(), 0);
    }

    #[test]
    fn test_list_all_tokens() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        store
            .create_token("user1", 30, Some("Token A".to_string()), Role::Write)
            .unwrap();
        store.create_token("user2", 30, None, Role::Read).unwrap();
        store
            .create_token("user1", 30, Some("Token B".to_string()), Role::Admin)
            .unwrap();

        let all = store.list_all_tokens();
        assert_eq!(all.len(), 3);

        // All file_ids should be 16 hex chars
        for entry in &all {
            assert_eq!(entry.file_id.len(), 16);
            assert!(entry.file_id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_file_id_matches_revoke() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();

        // Get file_id from list
        let entries = store.list_all_tokens();
        assert_eq!(entries.len(), 1);
        let file_id = &entries[0].file_id;

        // Revoke using file_id from list
        store.revoke_token(file_id).unwrap();

        // Token should be gone
        assert!(store.verify_token(&token).is_err());
        assert_eq!(store.list_all_tokens().len(), 0);
    }

    #[test]
    fn test_revoke_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();
        let file_id = sha256_hex(&token);
        let hash_prefix = &file_id[..16];

        assert!(store.verify_token(&token).is_ok());

        store.revoke_token(hash_prefix).unwrap();

        let result = store.verify_token(&token);
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[test]
    fn test_revoke_nonexistent_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let result = store.revoke_token("nonexistent12345");
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[test]
    fn test_revoke_all_for_user() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        store.create_token("user1", 30, None, Role::Write).unwrap();
        store.create_token("user1", 30, None, Role::Write).unwrap();
        store.create_token("user2", 30, None, Role::Read).unwrap();

        let revoked = store.revoke_all_for_user("user1");
        assert_eq!(revoked, 2);

        assert_eq!(store.list_tokens("user1").len(), 0);
        assert_eq!(store.list_tokens("user2").len(), 1);
    }

    #[tokio::test]
    async fn test_token_updates_last_used() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();

        store.verify_token(&token).unwrap();

        // last_used is deferred — flush to persist
        store.flush_last_used().await;

        let tokens = store.list_tokens("testuser");
        assert!(tokens[0].last_used.is_some());
    }

    #[test]
    fn test_verify_cache_hit() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();

        assert_eq!(
            store.cache.read().len(),
            0,
            "cache should be empty before first verify"
        );

        // First call: cold (disk + Argon2)
        let (user1, role1) = store.verify_token(&token).unwrap();
        assert_eq!(
            store.cache.read().len(),
            1,
            "cache should have 1 entry after first verify"
        );

        // Second call: should hit cache (no Argon2)
        let (user2, role2) = store.verify_token(&token).unwrap();
        assert_eq!(store.cache.read().len(), 1, "cache size unchanged on hit");

        assert_eq!(user1, user2);
        assert_eq!(role1, role2);
        assert_eq!(user1, "testuser");
        assert_eq!(role1, Role::Write);

        // Verify cache key is the full SHA-256 hex (64 chars), not a 16-char prefix
        let expected_key = sha256_hex(&token);
        assert!(
            store.cache.read().contains_key(&expected_key),
            "cache key must be full 64-char SHA-256"
        );
    }

    #[test]
    fn test_revoke_invalidates_cache() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();
        let file_id = sha256_hex(&token);
        let hash_prefix = &file_id[..16];

        // Populate cache
        assert!(store.verify_token(&token).is_ok());

        // Revoke
        store.revoke_token(hash_prefix).unwrap();

        // Cache should be invalidated
        let result = store.verify_token(&token);
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[test]
    fn test_revoke_all_clears_cache() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let token1 = store.create_token("alice", 30, None, Role::Write).unwrap();
        let token2 = store.create_token("alice", 30, None, Role::Read).unwrap();
        let token3 = store.create_token("bob", 30, None, Role::Write).unwrap();

        // Populate cache for all tokens
        store.verify_token(&token1).unwrap();
        store.verify_token(&token2).unwrap();
        store.verify_token(&token3).unwrap();
        assert_eq!(store.cache.read().len(), 3);

        // Revoke all tokens for alice
        let revoked = store.revoke_all_for_user("alice");
        assert_eq!(revoked, 2);

        // Alice's cache entries should be gone, bob's should remain
        assert_eq!(store.cache.read().len(), 1);
        assert!(
            store.verify_token(&token3).is_ok(),
            "bob's token should still work"
        );
        assert!(
            store.verify_token(&token1).is_err(),
            "alice's token should be revoked"
        );
    }

    #[test]
    fn test_token_with_description() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        store
            .create_token(
                "testuser",
                30,
                Some("CI/CD Pipeline".to_string()),
                Role::Admin,
            )
            .unwrap();

        let tokens = store.list_tokens("testuser");
        assert_eq!(tokens[0].description, Some("CI/CD Pipeline".to_string()));
    }

    // -- hash_prefix validation (path traversal prevention) --

    #[test]
    fn test_is_valid_hash_prefix() {
        assert!(is_valid_hash_prefix("0123456789abcdef"));
        assert!(is_valid_hash_prefix("deadbeefcafe1234"));
        // uppercase hex is rejected (token hashes are always lowercase)
        assert!(!is_valid_hash_prefix("0123456789ABCDEF"));
    }

    #[test]
    fn test_is_valid_hash_prefix_rejects_bad() {
        assert!(!is_valid_hash_prefix(""));
        assert!(!is_valid_hash_prefix("short"));
        assert!(!is_valid_hash_prefix("0123456789abcde")); // 15 chars
        assert!(!is_valid_hash_prefix("0123456789abcdef0")); // 17 chars
        assert!(!is_valid_hash_prefix("../../etc/passwd")); // path traversal
        assert!(!is_valid_hash_prefix("..%2f..%2fetcpwd")); // encoded traversal
        assert!(!is_valid_hash_prefix("zzzzzzzzzzzzzzzz")); // non-hex
    }

    #[test]
    fn test_revoke_rejects_path_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        // Create a decoy file that path traversal would target
        let decoy = temp_dir.path().join("../decoy.json");
        let _ = std::fs::write(&decoy, "should not be deleted");

        // Attempt path traversal
        let result = store.revoke_token("../decoy");
        assert!(matches!(result, Err(TokenError::NotFound)));
        let result = store.revoke_token("../../etc/passwd");
        assert!(matches!(result, Err(TokenError::NotFound)));
        let result = store.revoke_token("");
        assert!(matches!(result, Err(TokenError::NotFound)));
    }
}
