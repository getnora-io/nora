// Copyright (c) 2026 Volkov Pavel | DevITWay
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

/// TTL for cached token verifications (avoids Argon2 per request)
const CACHE_TTL: Duration = Duration::from_secs(300);

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

/// Token store for managing API tokens
#[derive(Clone)]
pub struct TokenStore {
    storage_path: PathBuf,
    /// In-memory cache: SHA256(token) -> verified result (avoids Argon2 per request)
    cache: Arc<RwLock<HashMap<String, CachedToken>>>,
    /// Pending last_used updates: file_id_prefix -> timestamp (flushed periodically)
    pending_last_used: Arc<RwLock<HashMap<String, u64>>>,
}

impl TokenStore {
    /// Create a new token store
    pub fn new(storage_path: &Path) -> Self {
        // Ensure directory exists with restricted permissions
        let _ = fs::create_dir_all(storage_path);
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(storage_path, fs::Permissions::from_mode(0o700));
        }
        Self {
            storage_path: storage_path.to_path_buf(),
            cache: Arc::new(RwLock::new(HashMap::new())),
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
                if cached.cached_at.elapsed() < CACHE_TTL {
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

        // Populate cache
        self.cache.write().insert(
            cache_key[..16].to_string(),
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

    /// List all tokens for a user
    pub fn list_tokens(&self, user: &str) -> Vec<TokenInfo> {
        let mut tokens = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.storage_path) {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    if let Ok(info) = serde_json::from_str::<TokenInfo>(&content) {
                        if info.user == user {
                            tokens.push(info);
                        }
                    }
                }
            }
        }

        tokens.sort_by(|a, b| b.created_at.cmp(&a.created_at));
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

    /// Remove a token from the in-memory cache (called on revoke)
    fn invalidate_cache(&self, hash_prefix: &str) {
        self.cache.write().remove(hash_prefix);
    }

    /// Revoke a token by its hash prefix
    pub fn revoke_token(&self, hash_prefix: &str) -> Result<(), TokenError> {
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

        count
    }
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

    #[test]
    fn test_token_hash_is_argon2() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let _token = store
            .create_token("testuser", 30, None, Role::Write)
            .unwrap();

        let tokens = store.list_tokens("testuser");
        assert!(tokens[0].token_hash.starts_with("$argon2"));
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

        // First call: cold (disk + Argon2)
        let (user1, role1) = store.verify_token(&token).unwrap();
        // Second call: should hit cache (no Argon2)
        let (user2, role2) = store.verify_token(&token).unwrap();

        assert_eq!(user1, user2);
        assert_eq!(role1, role2);
        assert_eq!(user1, "testuser");
        assert_eq!(role1, Role::Write);
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
}
