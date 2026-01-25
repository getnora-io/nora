use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const TOKEN_PREFIX: &str = "nra_";

/// API Token metadata stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub token_hash: String,
    pub user: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub last_used: Option<u64>,
    pub description: Option<String>,
}

/// Token store for managing API tokens
#[derive(Clone)]
pub struct TokenStore {
    storage_path: PathBuf,
}

impl TokenStore {
    /// Create a new token store
    pub fn new(storage_path: &Path) -> Self {
        // Ensure directory exists
        let _ = fs::create_dir_all(storage_path);
        Self {
            storage_path: storage_path.to_path_buf(),
        }
    }

    /// Generate a new API token for a user
    pub fn create_token(
        &self,
        user: &str,
        ttl_days: u64,
        description: Option<String>,
    ) -> Result<String, TokenError> {
        // Generate random token
        let raw_token = format!(
            "{}{}",
            TOKEN_PREFIX,
            Uuid::new_v4().to_string().replace("-", "")
        );
        let token_hash = hash_token(&raw_token);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = now + (ttl_days * 24 * 60 * 60);

        let info = TokenInfo {
            token_hash: token_hash.clone(),
            user: user.to_string(),
            created_at: now,
            expires_at,
            last_used: None,
            description,
        };

        // Save to file
        let file_path = self
            .storage_path
            .join(format!("{}.json", &token_hash[..16]));
        let json =
            serde_json::to_string_pretty(&info).map_err(|e| TokenError::Storage(e.to_string()))?;
        fs::write(&file_path, json).map_err(|e| TokenError::Storage(e.to_string()))?;

        Ok(raw_token)
    }

    /// Verify a token and return user info if valid
    pub fn verify_token(&self, token: &str) -> Result<String, TokenError> {
        if !token.starts_with(TOKEN_PREFIX) {
            return Err(TokenError::InvalidFormat);
        }

        let token_hash = hash_token(token);
        let file_path = self
            .storage_path
            .join(format!("{}.json", &token_hash[..16]));

        if !file_path.exists() {
            return Err(TokenError::NotFound);
        }

        let content =
            fs::read_to_string(&file_path).map_err(|e| TokenError::Storage(e.to_string()))?;
        let mut info: TokenInfo =
            serde_json::from_str(&content).map_err(|e| TokenError::Storage(e.to_string()))?;

        // Verify hash matches
        if info.token_hash != token_hash {
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

        // Update last_used
        info.last_used = Some(now);
        if let Ok(json) = serde_json::to_string_pretty(&info) {
            let _ = fs::write(&file_path, json);
        }

        Ok(info.user)
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

    /// Revoke a token by its hash prefix
    pub fn revoke_token(&self, hash_prefix: &str) -> Result<(), TokenError> {
        let file_path = self.storage_path.join(format!("{}.json", hash_prefix));

        if !file_path.exists() {
            return Err(TokenError::NotFound);
        }

        fs::remove_file(&file_path).map_err(|e| TokenError::Storage(e.to_string()))?;

        Ok(())
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

/// Hash a token using SHA256
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug)]
pub enum TokenError {
    InvalidFormat,
    NotFound,
    Expired,
    Storage(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "Invalid token format"),
            Self::NotFound => write!(f, "Token not found"),
            Self::Expired => write!(f, "Token expired"),
            Self::Storage(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for TokenError {}
