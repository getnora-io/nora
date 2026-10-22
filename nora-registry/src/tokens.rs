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
use std::sync::atomic::AtomicU64;
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

/// The longest lifetime a token is minted with, whatever a route asks for:
/// ten years. Applied by the store, so every route that mints is held to it.
pub const MAX_TOKEN_TTL_DAYS: u64 = 3650;

pub const SECS_PER_DAY: u64 = 24 * 60 * 60;

/// A lifetime of `ttl_days` days in seconds, at most [`MAX_TOKEN_TTL_DAYS`]
/// days: a lifetime too long to count in seconds is longer than the cap.
pub fn ttl_secs_for_days(ttl_days: u64) -> u64 {
    let max_secs = MAX_TOKEN_TTL_DAYS * SECS_PER_DAY;
    ttl_days
        .checked_mul(SECS_PER_DAY)
        .map_or(max_secs, |secs| secs.min(max_secs))
}

/// A token just minted, with what it was granted: what a route answers and
/// audits, the lifetime possibly less than it asked for.
#[derive(Debug)]
pub struct MintedToken {
    pub token: String,
    pub owner: String,
    pub role: Role,
    pub ttl_secs: u64,
}

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

/// Where a token operation stands, just past one of its steps: a test pauses
/// it there to play a race against another operation one step at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// A verify read the revocation count.
    CountRead,
    /// A verify read the token file.
    FileRead,
    /// The files lock is taken.
    Locked,
    /// A rewrite of a token file waits for the files lock.
    WaitsForLock,
    /// A revoke removed a token file.
    Removed,
    /// A revoke counted itself.
    Counted,
    /// A revoke purged the cache of what it removed.
    Evicted,
    /// The last_used flush read a token file.
    FlushRead,
    /// A token file was rewritten in place.
    Rewritten,
}

#[cfg(not(test))]
fn pause(_step: Step) {}

#[cfg(test)]
fn pause(step: Step) {
    tests::interleave::pause(step)
}

/// The token files on disk, and the steps a revoke and a verify take on them.
/// The order those steps must come in is held by the types here, which the
/// store cannot build itself:
/// - [`Held`], the files lock, is what removes or rewrites a token file, so a
///   rewrite (the last_used flush, the legacy-hash migration) that read a file
///   before a revoke cannot put it back after the revoke removed it;
/// - [`Read`], a token file as a verify read it, carries the revocation count
///   read before the file and is the only way into the verify cache, checked
///   against the count in the same step as the cache entry is made;
/// - [`Removed`], the files a revoke removed, is counted as a revoke
///   ([`Counted`]) before the cache can be purged of them, so the count and
///   the purge come after the removal, in that order.
mod files {
    use super::{pause, write_token_file, Step};
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The files lock, held.
    pub(super) struct Held<'a> {
        _lock: tokio::sync::MutexGuard<'a, ()>,
    }

    /// Take the files lock, waiting for a running rewrite or revoke.
    pub(super) async fn lock(files: &tokio::sync::Mutex<()>) -> Held<'_> {
        let held = match files.try_lock() {
            Ok(held) => held,
            Err(_) => {
                pause(Step::WaitsForLock);
                files.lock().await
            }
        };
        pause(Step::Locked);
        Held { _lock: held }
    }

    /// Take the files lock if nothing holds it.
    pub(super) fn try_lock(files: &tokio::sync::Mutex<()>) -> Option<Held<'_>> {
        let held = files.try_lock().ok()?;
        pause(Step::Locked);
        Some(Held { _lock: held })
    }

    impl Held<'_> {
        /// Remove the token file `file_id` from `dir`.
        pub(super) fn remove(&self, dir: &Path, file_id: &str) -> std::io::Result<Removed> {
            std::fs::remove_file(dir.join(format!("{file_id}.json")))?;
            pause(Step::Removed);
            Ok(Removed(vec![file_id.to_string()]))
        }

        /// Replace the token file at `path` with `json`.
        pub(super) fn rewrite(&self, path: &Path, json: &str) -> std::io::Result<()> {
            write_token_file(path, json)?;
            pause(Step::Rewritten);
            Ok(())
        }

        /// Replace the token file at `path` with `json`, off the async workers.
        pub(super) async fn rewrite_async(&self, path: &Path, json: &str) -> std::io::Result<()> {
            let tmp = path.with_extension("json.tmp");
            tokio::fs::write(&tmp, json).await?;
            super::set_file_permissions_600(&tmp);
            tokio::fs::rename(&tmp, path).await?;
            pause(Step::Rewritten);
            Ok(())
        }
    }

    /// The token files a revoke removed, by file id.
    pub(super) struct Removed(Vec<String>);

    impl Removed {
        /// These and `other`.
        pub(super) fn and(mut self, other: Removed) -> Removed {
            self.0.extend(other.0);
            self
        }

        /// Count the revoke, so a verify that read one of these files before
        /// it keeps its result out of the cache.
        pub(super) fn counted(self, revocations: &AtomicU64) -> Counted {
            revocations.fetch_add(1, Ordering::SeqCst);
            pause(Step::Counted);
            Counted(self.0)
        }
    }

    /// The token files of a revoke that has been counted, by file id.
    pub(super) struct Counted(Vec<String>);

    impl Counted {
        /// Drop the cached verifications of these files from `cache`.
        pub(super) fn purge<V>(&self, cache: &mut HashMap<String, V>) {
            cache.retain(|key, _| {
                !self
                    .0
                    .iter()
                    .any(|file_id| key.starts_with(file_id.as_str()))
            });
        }

        /// How many files were removed.
        pub(super) fn len(&self) -> usize {
            self.0.len()
        }
    }

    /// A token file as a verify read it.
    pub(super) struct Read {
        /// The revocation count read before the file.
        revocations: u64,
        content: String,
    }

    /// Read the token file at `path` for a verify: the revocation count
    /// first, then the file.
    pub(super) fn read(revocations: &AtomicU64, path: &Path) -> std::io::Result<Read> {
        let seen = revocations.load(Ordering::SeqCst);
        pause(Step::CountRead);
        let content = std::fs::read_to_string(path)?;
        pause(Step::FileRead);
        Ok(Read {
            revocations: seen,
            content,
        })
    }

    impl Read {
        pub(super) fn content(&self) -> &str {
            &self.content
        }

        /// Put `verified` into `cache` under `key`, unless a revoke came in
        /// since the file was read. Takes the cache itself, so the count is
        /// checked while the cache is held for the entry.
        pub(super) fn cache_unless_revoked<V>(
            &self,
            revocations: &AtomicU64,
            cache: &mut HashMap<String, V>,
            key: String,
            verified: V,
        ) {
            if revocations.load(Ordering::SeqCst) == self.revocations {
                cache.insert(key, verified);
            }
        }
    }
}

/// What a revoke removes.
enum Revoke<'a> {
    /// The token whose file id is this.
    Token(&'a str),
    /// Every token of this user.
    User(&'a str),
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
    /// Held to rewrite an existing token file or to remove one, so a rewrite
    /// (the last_used flush, the legacy-hash migration) that read the file
    /// before a revoke cannot put it back after the revoke removed it.
    file_lock: Arc<tokio::sync::Mutex<()>>,
    /// Bumped by every revoke before it purges the cache. A verify reads it
    /// before it reads the token file and caches its result only if no revoke
    /// came in between, so a verify racing a revoke cannot cache the revoked
    /// token (see [`files`]).
    revocations: Arc<AtomicU64>,
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
            file_lock: Arc::new(tokio::sync::Mutex::new(())),
            revocations: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Generate a new API token for a user, living `ttl_days` days — at most
    /// [`MAX_TOKEN_TTL_DAYS`].
    pub fn create_token(
        &self,
        user: &str,
        ttl_days: u64,
        description: Option<String>,
        role: Role,
    ) -> Result<String, TokenError> {
        self.mint_token(user, ttl_secs_for_days(ttl_days), description, role)
            .map(|minted| minted.token)
    }

    /// Generate a new API token living `ttl_secs` seconds — at most
    /// [`MAX_TOKEN_TTL_DAYS`] days — and report the lifetime granted. Seconds,
    /// for a caller whose own credential lives less than a day: the token it
    /// mints must not outlive it.
    pub fn mint_token(
        &self,
        user: &str,
        ttl_secs: u64,
        description: Option<String>,
        role: Role,
    ) -> Result<MintedToken, TokenError> {
        let granted_role = role.clone();
        let ttl_secs = ttl_secs.min(MAX_TOKEN_TTL_DAYS * SECS_PER_DAY);
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

        let expires_at = now.saturating_add(ttl_secs);

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
        write_token_file(&file_path, &json).map_err(|e| TokenError::Storage(e.to_string()))?;

        Ok(MintedToken {
            token: raw_token,
            owner: user.to_string(),
            role: granted_role,
            ttl_secs,
        })
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

        // Slow path: read from disk and verify Argon2. A revoke after the
        // read keeps the result out of the cache (see `revocations`).
        let file_path = self.storage_path.join(format!("{}.json", &cache_key[..16]));

        let read = match files::read(&self.revocations, &file_path) {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(TokenError::NotFound);
            }
            Err(e) => return Err(TokenError::Storage(e.to_string())),
        };

        let mut info: TokenInfo =
            serde_json::from_str(read.content()).map_err(|e| TokenError::Storage(e.to_string()))?;

        // Verify hash: try Argon2id first, fall back to legacy SHA256
        let hash_valid = if info.token_hash.starts_with("$argon2") {
            verify_token_argon2(token, &info.token_hash)
        } else {
            // Legacy SHA256 hash (no salt) — verify and migrate
            let legacy_hash = sha256_hex(token);
            if info.token_hash == legacy_hash {
                // Migrate to Argon2id. Best effort: skipped while another
                // rewrite or a revoke holds the file, and when a revoke
                // removed the file since it was read; a later verify retries.
                if let Ok(new_hash) = hash_token_argon2(token) {
                    info.token_hash = new_hash;
                    if let Ok(json) = serde_json::to_string_pretty(&info) {
                        if let Some(held) = files::try_lock(&self.file_lock) {
                            if file_path.exists() {
                                let _ = held.rewrite(&file_path, &json);
                            }
                        }
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

        // Populate cache (key must match the fast-path lookup: full 64-char
        // SHA-256 hex), unless a revoke came in since the file was read.
        self.cache_unless_revoked(
            &read,
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
            // From the read to the rename: a revoke waits, so it removes the
            // rewritten file instead of being undone by it.
            let held = files::lock(&self.file_lock).await;
            let content = match tokio::fs::read_to_string(&file_path).await {
                Ok(c) => c,
                Err(_) => continue,
            };
            pause(Step::FlushRead);
            let mut info: TokenInfo = match serde_json::from_str(&content) {
                Ok(i) => i,
                Err(_) => continue,
            };
            info.last_used = Some(*timestamp);
            // Atomic replace (write temp + rename), NOT an in-place `fs::write`:
            // this runs every 30s for every active token while `verify_token`
            // reads the same file on its cache-miss path. An in-place write
            // truncates first, so a concurrent read can observe a torn/empty
            // file — a VALID token then 401s ("Invalid username or password")
            // until a clean read repopulates the verify cache.
            if let Ok(json) = serde_json::to_string_pretty(&info) {
                let _ = held.rewrite_async(&file_path, &json).await;
            }
        }

        tracing::debug!(count = pending.len(), "Flushed pending last_used updates");
    }

    /// Cache a verified token, unless a revoke came in since the verify read
    /// its file.
    fn cache_unless_revoked(&self, read: &files::Read, cache_key: String, verified: CachedToken) {
        read.cache_unless_revoked(
            &self.revocations,
            &mut self.cache.write(),
            cache_key,
            verified,
        );
    }

    /// Count a revoke, then drop the cached verifications of the files it
    /// removed, so a verify that read a token file before the revoke cannot
    /// cache it afterwards. Answers how many files were removed.
    fn evict(&self, removed: files::Removed) -> usize {
        let counted = removed.counted(&self.revocations);
        counted.purge(&mut self.cache.write());
        pause(Step::Evicted);
        counted.len()
    }

    /// The one way a token is revoked. Under the files lock, so no rewrite of
    /// a token file runs meanwhile: remove the files `which` selects, then
    /// count the revoke and purge the cache of them. Once it returns, the
    /// tokens removed are refused, from the cache too.
    async fn revoke(&self, which: Revoke<'_>) -> Result<usize, TokenError> {
        let held = files::lock(&self.file_lock).await;
        let removed = match which {
            Revoke::Token(file_id) => match held.remove(&self.storage_path, file_id) {
                Ok(removed) => Some(removed),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(TokenError::NotFound)
                }
                Err(e) => return Err(TokenError::Storage(e.to_string())),
            },
            Revoke::User(user) => self
                .list_tokens(user)
                .iter()
                .filter_map(|token| held.remove(&self.storage_path, &token.file_id).ok())
                .reduce(files::Removed::and),
        };
        Ok(removed.map_or(0, |removed| self.evict(removed)))
    }

    /// Revoke a token by its hash prefix.
    ///
    /// `hash_prefix` must be exactly 16 lowercase hexadecimal characters (the
    /// first 16 chars of SHA-256(token)). Anything else is rejected to prevent
    /// path-traversal attacks via crafted prefixes like `../../etc/passwd`.
    ///
    /// Waits for a running rewrite of the file (the last_used flush), so the
    /// revoke is never undone by it; once this returns the token is refused.
    pub async fn revoke_token(&self, hash_prefix: &str) -> Result<(), TokenError> {
        // SECURITY: validate format before building filesystem path
        if !is_valid_hash_prefix(hash_prefix) {
            return Err(TokenError::NotFound);
        }
        self.revoke(Revoke::Token(hash_prefix)).await.map(drop)
    }

    /// Revoke all tokens for a user. Waits for a running rewrite of a token
    /// file, like [`TokenStore::revoke_token`].
    pub async fn revoke_all_for_user(&self, user: &str) -> usize {
        self.revoke(Revoke::User(user)).await.unwrap_or(0)
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

/// Write a token file atomically: temp file in the same directory, permissions
/// fixed, then rename over the target. `verify_token` reads these files on its
/// cache-miss path while background rewrites happen, and a plain `fs::write`
/// truncates in place — a concurrent reader can observe a torn/empty file and
/// fail a valid token. Listings skip the temp name (extension is `tmp`, not
/// `json`), and `is_valid_hash_prefix` keeps it out of revoke paths.
fn write_token_file(path: &Path, json: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json)?;
    set_file_permissions_600(&tmp);
    fs::rename(&tmp, path)
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

    /// Plays token operations against each other one step at a time, in every
    /// order their steps can take. Each operation runs on a thread of its own
    /// and pauses at every [`Step`] it passes; one operation at a time is let
    /// on to its next step, so a run is the same whatever the timing. A run
    /// that would let an operation wait for the files lock held by another
    /// one lets the holder on instead.
    pub(super) mod interleave {
        use super::super::Step;
        use std::cell::RefCell;
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::Duration;

        /// Where every operation of a run stands.
        #[derive(Default)]
        struct Turns {
            /// The step each operation is paused past; `None` while it runs.
            paused: Vec<Option<Step>>,
            done: Vec<bool>,
            /// The operation let on to its next step.
            running: Option<usize>,
        }

        #[derive(Default)]
        struct Run {
            turns: Mutex<Turns>,
            changed: Condvar,
        }

        thread_local! {
            static OPERATION: RefCell<Option<(Arc<Run>, usize)>> = const { RefCell::new(None) };
        }

        /// Pause the operation on this thread past `step` until its turn.
        /// A no-op on a thread outside a run.
        pub(in crate::tokens) fn pause(step: Step) {
            let Some((run, me)) = OPERATION.with(|op| op.borrow().clone()) else {
                return;
            };
            let mut turns = run.turns.lock().unwrap();
            turns.paused[me] = Some(step);
            turns.running = None;
            run.changed.notify_all();
            while turns.running != Some(me) {
                turns = run.changed.wait(turns).unwrap();
            }
            turns.paused[me] = None;
        }

        /// An operation of a run, on a thread of its own.
        pub(in crate::tokens) type Operation = Box<dyn FnOnce() + Send>;

        /// Run `operations` to the end, choosing at each turn which one goes
        /// on with `choose`, among those that can: `can_go(step)` is false for
        /// one paused at `step` that would block. Answers the steps taken, in
        /// order, by operation.
        pub(in crate::tokens) fn run(
            operations: Vec<Operation>,
            can_go: &dyn Fn(Step) -> bool,
            choose: &mut dyn FnMut(&[usize]) -> usize,
        ) -> Vec<(usize, Option<Step>)> {
            let run = Arc::new(Run::default());
            {
                let mut turns = run.turns.lock().unwrap();
                turns.paused = vec![None; operations.len()];
                turns.done = vec![false; operations.len()];
            }
            let threads: Vec<_> = operations
                .into_iter()
                .enumerate()
                .map(|(me, operation)| {
                    let run = run.clone();
                    std::thread::spawn(move || {
                        OPERATION.with(|op| *op.borrow_mut() = Some((run.clone(), me)));
                        // Every operation starts paused, before its first step.
                        {
                            let mut turns = run.turns.lock().unwrap();
                            while turns.running != Some(me) {
                                turns = run.changed.wait(turns).unwrap();
                            }
                        }
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
                        let mut turns = run.turns.lock().unwrap();
                        turns.done[me] = true;
                        turns.running = None;
                        run.changed.notify_all();
                        drop(turns);
                        if let Err(panic) = outcome {
                            std::panic::resume_unwind(panic);
                        }
                    })
                })
                .collect();

            let mut taken = Vec::new();
            let mut started = vec![false; threads.len()];
            loop {
                let mut turns = run.turns.lock().unwrap();
                let settled = |t: &Turns| {
                    t.running.is_none()
                        && (0..t.done.len())
                            .all(|i| t.done[i] || t.paused[i].is_some() || !started[i])
                };
                while !settled(&turns) {
                    let (next, timeout) = run
                        .changed
                        .wait_timeout(turns, Duration::from_secs(30))
                        .unwrap();
                    turns = next;
                    assert!(
                        !timeout.timed_out() || settled(&turns),
                        "an operation neither paused nor finished: {taken:?}"
                    );
                }
                let ready: Vec<usize> = (0..turns.done.len())
                    .filter(|&i| !turns.done[i])
                    .filter(|&i| turns.paused[i].is_none_or(can_go))
                    .collect();
                if ready.is_empty() {
                    assert!(
                        turns.done.iter().all(|done| *done),
                        "no operation can go on: {taken:?}"
                    );
                    break;
                }
                let next = choose(&ready);
                taken.push((next, turns.paused[next]));
                started[next] = true;
                turns.running = Some(next);
                run.changed.notify_all();
            }
            for thread in threads {
                if let Err(panic) = thread.join() {
                    std::panic::resume_unwind(panic);
                }
            }
            taken
        }

        /// Call `play` once for every order of the turns it can take: `play`
        /// runs one case, handing [`run`] the chooser it is given. Answers how
        /// many orders were played.
        pub(in crate::tokens) fn every_order(
            mut play: impl FnMut(&mut dyn FnMut(&[usize]) -> usize),
        ) -> usize {
            // The choice made at each turn of the order being played, out of
            // how many.
            let mut order: Vec<(usize, usize)> = Vec::new();
            let mut played = 0;
            loop {
                let mut turn = 0;
                let mut taken: Vec<(usize, usize)> = Vec::new();
                play(&mut |ready| {
                    let choice = order.get(turn).map_or(0, |&(choice, _)| choice);
                    assert!(choice < ready.len(), "a run took another way on a replay");
                    taken.push((choice, ready.len()));
                    turn += 1;
                    ready[choice]
                });
                played += 1;
                order = taken;
                while let Some((choice, of)) = order.pop() {
                    if choice + 1 < of {
                        order.push((choice + 1, of));
                        break;
                    }
                }
                if order.is_empty() {
                    return played;
                }
            }
        }
    }

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
        futures::executor::block_on(replica_a.revoke_token(&hash_prefix)).unwrap();

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
        futures::executor::block_on(store.revoke_token(file_id)).unwrap();

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

        futures::executor::block_on(store.revoke_token(hash_prefix)).unwrap();

        let result = store.verify_token(&token);
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[test]
    fn test_revoke_nonexistent_token() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        let result = futures::executor::block_on(store.revoke_token("nonexistent12345"));
        assert!(matches!(result, Err(TokenError::NotFound)));
    }

    #[test]
    fn test_revoke_all_for_user() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        store.create_token("user1", 30, None, Role::Write).unwrap();
        store.create_token("user1", 30, None, Role::Write).unwrap();
        store.create_token("user2", 30, None, Role::Read).unwrap();

        let revoked = futures::executor::block_on(store.revoke_all_for_user("user1"));
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
        futures::executor::block_on(store.revoke_token(hash_prefix)).unwrap();

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
        let revoked = futures::executor::block_on(store.revoke_all_for_user("alice"));
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

    /// A corrupt/torn token file must surface as `Storage`, not `NotFound` —
    /// the auth middleware maps `Storage` to 503 (retryable outage) and
    /// everything else to 401 (credential verdict). Misclassifying a torn file
    /// as `NotFound` turns a storage blip into an auth denial.
    #[test]
    fn verify_reports_storage_error_on_corrupt_file() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());
        let token = store.create_token("ci", 30, None, Role::Read).unwrap();

        // Corrupt the on-disk file the way a torn in-place write would.
        let file = temp_dir
            .path()
            .join(format!("{}.json", &sha256_hex(&token)[..16]));
        std::fs::write(&file, "{\"token_ha").unwrap();

        assert!(matches!(
            store.verify_token(&token),
            Err(TokenError::Storage(_))
        ));
    }

    /// `flush_last_used` must leave the token file whole (atomic replace) with
    /// the timestamp applied, and clean up its temp file — a verify racing the
    /// flush then can never observe a truncated file from NORA's own writes.
    #[tokio::test]
    async fn flush_last_used_replaces_file_atomically() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());
        let token = store.create_token("ci", 30, None, Role::Read).unwrap();

        // Schedules a pending last_used update.
        store.verify_token(&token).unwrap();
        store.flush_last_used().await;

        let prefix = &sha256_hex(&token)[..16];
        let file = temp_dir.path().join(format!("{prefix}.json"));
        let info: TokenInfo =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert!(info.last_used.is_some(), "flush must apply the timestamp");
        assert!(
            !temp_dir.path().join(format!("{prefix}.json.tmp")).exists(),
            "temp file must be renamed away, not left behind"
        );
        // And the token still verifies from disk (fresh store = no warm cache).
        let cold = TokenStore::new(temp_dir.path());
        assert!(cold.verify_token(&token).is_ok());
    }

    /// A token of `user` written straight into `dir`, hashed at the lowest
    /// Argon2 cost: a verify checks it like any other, only much sooner, so
    /// every order of a race can be played.
    fn cheap_token(dir: &Path, user: &str) -> String {
        let token = format!("{TOKEN_PREFIX}{}", Uuid::new_v4().simple());
        let params = argon2::Params::new(8, 1, 1, None).unwrap();
        let token_hash = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password(token.as_bytes(), &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let info = TokenInfo {
            token_hash,
            user: user.to_string(),
            created_at: now,
            expires_at: now + 86_400,
            last_used: None,
            description: None,
            role: Role::Write,
        };
        fs::write(
            token_path(dir, &token),
            serde_json::to_string_pretty(&info).unwrap(),
        )
        .unwrap();
        token
    }

    fn token_path(dir: &Path, token: &str) -> PathBuf {
        dir.join(format!("{}.json", &sha256_hex(token)[..16]))
    }

    /// `operation` to the end on a runtime of its own thread.
    fn on_runtime<F: std::future::Future>(operation: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(operation)
    }

    /// Every way to revoke alice's token: by its prefix, as the API and the UI
    /// routes do, and with every token of hers.
    fn revokes() -> [(&'static str, fn(&TokenStore, &str)); 2] {
        [
            ("by prefix", |store, token| {
                on_runtime(store.revoke_token(&sha256_hex(token)[..16])).unwrap()
            }),
            ("every token of the user", |store, _| {
                assert_eq!(on_runtime(store.revoke_all_for_user("alice")), 1)
            }),
        ]
    }

    /// Whether an operation on `store` paused at `step` can go on: not one
    /// that waits for the files lock while another operation holds it.
    fn can_go(store: &TokenStore) -> impl Fn(Step) -> bool + '_ {
        move |step| step != Step::WaitsForLock || store.file_lock.try_lock().is_ok()
    }

    /// A verify racing a revoke, in every order of their steps and with the
    /// token cached or not beforehand, leaves the token refused once the
    /// revoke is done: the verify neither keeps it cached nor caches it again.
    /// Bob's token, which the revoke leaves alone, is still served.
    #[test]
    fn a_verify_racing_a_revoke_in_any_order_leaves_the_token_refused() {
        for (path, revoke) in revokes() {
            for cached in [false, true] {
                let played = interleave::every_order(|choose| {
                    let dir = TempDir::new().unwrap();
                    let store = TokenStore::new(dir.path());
                    let token = cheap_token(dir.path(), "alice");
                    let kept = cheap_token(dir.path(), "bob");
                    if cached {
                        store.verify_token(&token).unwrap();
                    }
                    let verify: interleave::Operation = {
                        let (store, token) = (store.clone(), token.clone());
                        Box::new(move || drop(store.verify_token(&token)))
                    };
                    let revoking: interleave::Operation = {
                        let (store, token) = (store.clone(), token.clone());
                        Box::new(move || revoke(&store, &token))
                    };
                    let taken = interleave::run(vec![verify, revoking], &can_go(&store), choose);
                    assert!(
                        matches!(store.verify_token(&token), Err(TokenError::NotFound)),
                        "{path}, cached {cached}: the revoked token is served after {taken:?}"
                    );
                    assert!(store.verify_token(&kept).is_ok(), "{path}: {taken:?}");
                });
                assert!(played > 1, "{path}: {played} orders");
            }
        }
    }

    /// The last_used flush racing a revoke, in every order of their steps,
    /// leaves the token revoked: the flush does not put the file back, and the
    /// token is refused by this store and by one that starts afresh.
    #[test]
    fn a_rewrite_racing_a_revoke_in_any_order_leaves_the_token_revoked() {
        for (path, revoke) in revokes() {
            let played = interleave::every_order(|choose| {
                let dir = TempDir::new().unwrap();
                let store = TokenStore::new(dir.path());
                let token = cheap_token(dir.path(), "alice");
                // Gives the flush a last_used to write.
                store.verify_token(&token).unwrap();
                let flush: interleave::Operation = {
                    let store = store.clone();
                    Box::new(move || on_runtime(store.flush_last_used()))
                };
                let revoking: interleave::Operation = {
                    let (store, token) = (store.clone(), token.clone());
                    Box::new(move || revoke(&store, &token))
                };
                let taken = interleave::run(vec![flush, revoking], &can_go(&store), choose);
                assert!(
                    !token_path(dir.path(), &token).exists(),
                    "{path}: the flush put the revoked token back after {taken:?}"
                );
                assert!(
                    matches!(store.verify_token(&token), Err(TokenError::NotFound)),
                    "{path}: {taken:?}"
                );
                assert!(TokenStore::new(dir.path()).verify_token(&token).is_err());
            });
            assert!(played > 1, "{path}: {played} orders");
        }
    }

    /// A token file is removed only by the files lock's `remove`, and written
    /// over only by the files lock's rewrites and by a mint, which writes a new
    /// one (white list): a revoke or a rewrite that went another way would
    /// skip the lock or the order [`files`] holds. Needles are built at run
    /// time so this text does not match.
    #[test]
    fn token_files_are_removed_and_written_only_through_the_files_lock() {
        use std::collections::{BTreeMap, BTreeSet};
        let source = include_str!("tokens.rs");
        let code = &source[..source.find(&["mod", " tests {"].concat()).unwrap()];
        let needles = [
            ["remove", "_file"].concat(),
            ["remove", "_dir"].concat(),
            ["rename", "("].concat(),
            ["fs::", "write("].concat(),
            ["write_token", "_file("].concat(),
        ];
        let mut found: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut function = "";
        for line in code.lines().filter(|l| !l.trim_start().starts_with("//")) {
            if let Some((_, rest)) = line.split_once("fn ") {
                function = rest
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .next()
                    .unwrap_or("");
            }
            for needle in &needles {
                if line.contains(needle.as_str()) {
                    found.entry(needle).or_default().insert(function);
                }
            }
        }
        let allowed: BTreeMap<&str, BTreeSet<&str>> = [
            (needles[0].as_str(), BTreeSet::from(["remove"])),
            (
                needles[2].as_str(),
                BTreeSet::from(["rewrite_async", "write_token_file"]),
            ),
            (
                needles[3].as_str(),
                BTreeSet::from(["rewrite_async", "write_token_file"]),
            ),
            (
                needles[4].as_str(),
                BTreeSet::from(["mint_token", "rewrite", "write_token_file"]),
            ),
        ]
        .into();
        assert_eq!(found, allowed);
    }

    /// The legacy-hash migration rewrites the token file on a verify. Racing a
    /// revoke, in every order of their steps, it leaves the token revoked: it
    /// does not put the file back, and the token is refused afterwards.
    #[test]
    fn a_migration_racing_a_revoke_in_any_order_leaves_the_token_revoked() {
        let raw_token = "nra_0123456789abcdef0123456789abcdef";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let info = TokenInfo {
            token_hash: sha256_hex(raw_token),
            user: "alice".to_string(),
            created_at: now,
            expires_at: now + 86400,
            last_used: None,
            description: None,
            role: Role::Write,
        };
        for (path, revoke) in revokes() {
            let played = interleave::every_order(|choose| {
                let dir = TempDir::new().unwrap();
                let file = token_path(dir.path(), raw_token);
                fs::write(&file, serde_json::to_string_pretty(&info).unwrap()).unwrap();
                let store = TokenStore::new(dir.path());
                let migrate: interleave::Operation = {
                    let store = store.clone();
                    Box::new(move || drop(store.verify_token(raw_token)))
                };
                let revoking: interleave::Operation = {
                    let store = store.clone();
                    Box::new(move || revoke(&store, raw_token))
                };
                let taken = interleave::run(vec![migrate, revoking], &can_go(&store), choose);
                assert!(
                    !file.exists(),
                    "{path}: the migration put the revoked token back after {taken:?}"
                );
                assert!(
                    matches!(store.verify_token(raw_token), Err(TokenError::NotFound)),
                    "{path}: {taken:?}"
                );
            });
            assert!(played > 1, "{path}: {played} orders");
        }
    }

    /// Every mint gets at most MAX_TOKEN_TTL_DAYS days, however long it asks
    /// for: a lifetime that overflows when counted in seconds included, which
    /// used to wrap around to a token of a few hours.
    #[test]
    fn create_token_caps_the_lifetime_centrally() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());
        let ten_years = 3650 * 86_400;
        for (asked, want) in [
            (30, 30 * 86_400),
            (3650, ten_years),
            (3651, ten_years),
            (1_000_000_000, ten_years),
            (213_503_982_334_602, ten_years),
            (u64::MAX, ten_years),
        ] {
            let token = store.create_token("u", asked, None, Role::Read).unwrap();
            let prefix = &sha256_hex(&token)[..16];
            let entry = store
                .list_all_tokens()
                .into_iter()
                .find(|t| t.file_id == prefix)
                .unwrap();
            assert_eq!(
                entry.expires_at - entry.created_at,
                want,
                "ttl_days={asked}"
            );
        }
    }

    /// The store reports the lifetime it granted, not the one asked for: a
    /// route answers and audits what the token really lives.
    #[test]
    fn mint_token_reports_the_lifetime_granted() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());
        for (asked, granted) in [(900, 900), (u64::MAX, 3650 * 86_400)] {
            let minted = store.mint_token("u", asked, None, Role::Write).unwrap();
            assert_eq!(minted.ttl_secs, granted, "asked {asked}");
            assert_eq!((minted.owner.as_str(), minted.role), ("u", Role::Write));
            let entry = store
                .list_all_tokens()
                .into_iter()
                .find(|t| t.file_id == sha256_hex(&minted.token)[..16])
                .unwrap();
            assert_eq!(entry.expires_at - entry.created_at, granted);
        }
    }

    #[test]
    fn test_revoke_rejects_path_traversal() {
        let temp_dir = TempDir::new().unwrap();
        let store = TokenStore::new(temp_dir.path());

        // Create a decoy file that path traversal would target
        let decoy = temp_dir.path().join("../decoy.json");
        let _ = std::fs::write(&decoy, "should not be deleted");

        // Attempt path traversal
        let result = futures::executor::block_on(store.revoke_token("../decoy"));
        assert!(matches!(result, Err(TokenError::NotFound)));
        let result = futures::executor::block_on(store.revoke_token("../../etc/passwd"));
        assert!(matches!(result, Err(TokenError::NotFound)));
        let result = futures::executor::block_on(store.revoke_token(""));
        assert!(matches!(result, Err(TokenError::NotFound)));
    }
}
