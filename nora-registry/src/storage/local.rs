// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use async_trait::async_trait;
use axum::body::Bytes;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::{FileMeta, Result, StorageBackend, StorageError};
use crate::hash_pin_store::HashPinStore;

/// The hash-pin sidecar is backend bookkeeping, not a stored artifact: it is
/// held out of listings and the size gauge, like the `tmp/` staging directory.
const PIN_FILE: &str = ".nora-pins.ndjson";

/// Monotonic counter for unique temp file names (atomic — no collisions).
static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The next temp-name sequence number, unique in this process. Relaxed ordering: the
/// counter only makes names unique, it orders nothing.
fn next_tmp_seq() -> u64 {
    #[cfg(test)]
    if let Some(seq) = tests::NEXT_TMP_SEQ.with(|next| next.replace(None)) {
        tests::NEXT_TMP_SEQ.with(|next| next.set(Some(seq + 1)));
        return seq;
    }
    TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A temp path beside `path`, `<name>.tmp.<pid>.<seq>`: where a write stages when it
/// cannot use the staging directory.
fn tmp_path_with_seq(path: &Path, seq: u64) -> PathBuf {
    path.with_extension(format!("tmp.{}.{}", std::process::id(), seq))
}

/// How many temp names a write tries before giving up: a name is skipped when a file
/// already has it (see [`LocalStorage::create_tmp`]).
const TMP_CREATE_ATTEMPTS: u32 = 8;

/// The lock file of an instance's staging directory.
const STAGING_LOCK_FILE: &str = "lock";
/// Name prefix of a staging directory that is still being created.
const STAGING_NEW_PREFIX: &str = ".new-";
/// A staging directory still named `.new-*` after this long was abandoned half-created:
/// creating one takes a few syscalls.
const STAGING_NEW_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(3600);
/// `EXDEV`: a rename across filesystems.
const EXDEV: i32 = 18;

/// Name of a temp file in a staging directory.
fn staging_tmp_name(seq: u64) -> String {
    format!("{seq}.tmp")
}

/// Where a write creates its temp file.
#[derive(Debug, Clone, Copy)]
enum TmpPlace {
    /// This instance's staging directory; beside the key while it is unavailable.
    Staging,
    /// Beside the key: the rename out of staging crossed a filesystem.
    BesideKey,
}

/// One instance's staging directory, `<root>/.nora-staging/<id>/`.
///
/// Writes in progress live here rather than beside their key, where a temp file that
/// outlived its process (SIGKILL, OOM, a power cut: no `Drop` ran) looks like a key
/// and nothing ever removes it. The instance holds an exclusive `flock` on the `lock`
/// file inside for its whole life; the kernel drops that lock with the process's last
/// file descriptor, however it ends. A starting instance removes every staging
/// directory whose lock it can take: no live process owns it. A PID could not tell
/// owners apart — every container's process is PID 1. Two instances on one volume
/// (a rolling update) each keep their own directory and never remove the other's.
///
/// The directory is created as `.new-<id>` with its lock already held and only then
/// renamed to `<id>`, so a directory under its final name always has a held lock or
/// a dead owner. A directory without a lock file has a dead owner too (it was being
/// removed). The staging directory is not a storage key: `validate_storage_key`
/// refuses it.
#[derive(Debug)]
struct Staging {
    dir: PathBuf,
    _lock: std::fs::File,
}

/// Opened on the first write, which also removes dead instances' staging; `None` when
/// it cannot be opened, and writes then stage beside the key as before.
type StagingCell = Arc<std::sync::OnceLock<Option<Staging>>>;

/// Take an exclusive `flock` on `file` without waiting: `Ok(false)` when another open
/// file description holds it, in this process or another.
#[cfg(unix)]
fn try_lock_exclusive(file: &std::fs::File) -> std::io::Result<bool> {
    use rustix::fs::{flock, FlockOperation};
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(e) if e == rustix::io::Errno::WOULDBLOCK => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Create this instance's staging directory under `root`, after removing the ones
/// dead instances left. See [`Staging`].
#[cfg(unix)]
fn open_staging(root: &Path) -> std::io::Result<Staging> {
    let staging_root = root.join(crate::validation::STAGING_DIR);
    std::fs::create_dir_all(&staging_root)?;
    remove_dead_staging(&staging_root);
    let id = uuid::Uuid::new_v4().simple().to_string();
    let new = staging_root.join(format!("{STAGING_NEW_PREFIX}{id}"));
    std::fs::create_dir(&new)?;
    let created = (|| {
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(new.join(STAGING_LOCK_FILE))?;
        if !try_lock_exclusive(&lock)? {
            return Err(std::io::Error::other("a new staging lock is already held"));
        }
        let dir = staging_root.join(&id);
        std::fs::rename(&new, &dir)?;
        Ok(Staging { dir, _lock: lock })
    })();
    if created.is_err() {
        let _ = std::fs::remove_dir_all(&new);
    }
    created
}

#[cfg(not(unix))]
fn open_staging(_root: &Path) -> std::io::Result<Staging> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "staging needs flock",
    ))
}

/// The directory a listing names must be readable: a listing that silently skipped it would
/// answer "nothing here" for files that are there (a published npm package would read as
/// unpublished). A directory deeper down that cannot be read is still skipped, as before.
fn readable_listing_root(root: &Path) -> std::result::Result<(), StorageError> {
    match std::fs::read_dir(root) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StorageError::Io(e)),
    }
}

/// Remove the staging directories of dead instances: those whose lock can be taken,
/// those without a lock file, and `.new-*` ones abandoned half-created. A directory
/// whose lock is held belongs to a live instance and is left alone, and so is any
/// entry that is not a directory (a symlink included).
#[cfg(unix)]
fn remove_dead_staging(staging_root: &Path) {
    let Ok(entries) = std::fs::read_dir(staging_root) else {
        return;
    };
    let mut removed = 0u32;
    for entry in entries.flatten() {
        // `DirEntry::metadata` does not follow symlinks.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let dir = entry.path();
        let name = entry.file_name();
        // Held until the directory is gone, so no other starting instance races us.
        let mut held = None;
        let dead = if name.to_string_lossy().starts_with(STAGING_NEW_PREFIX) {
            meta.modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age >= STAGING_NEW_MAX_AGE)
        } else {
            match std::fs::File::open(dir.join(STAGING_LOCK_FILE)) {
                Ok(lock) => match try_lock_exclusive(&lock) {
                    Ok(true) => {
                        held = Some(lock);
                        true
                    }
                    Ok(false) => false,
                    Err(e) => {
                        tracing::warn!(dir = %dir.display(), error = %e, "cannot test a staging lock; leaving it");
                        false
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => false,
            }
        };
        if dead && std::fs::remove_dir_all(&dir).is_ok() {
            removed += 1;
        }
        drop(held);
    }
    if removed > 0 {
        tracing::info!(removed, dir = %staging_root.display(), "Removed the staging directories of dead instances");
    }
}

/// This instance's staging directory, opening it on first use.
fn staging_dir_sync<'a>(
    cell: &'a std::sync::OnceLock<Option<Staging>>,
    root: &Path,
) -> Option<&'a Path> {
    cell.get_or_init(|| match open_staging(root) {
        Ok(staging) => Some(staging),
        Err(e) => {
            tracing::warn!(root = %root.display(), error = %e, "No staging directory; writes stage their temp file beside the key");
            None
        }
    })
    .as_ref()
    .map(|staging| staging.dir.as_path())
}

/// The directory a listing for `prefix` can start from: the one its last `/` names, so
/// `npm/pkg/versions/` walks that directory and not the whole store. `None` for a prefix
/// inside the staging area, which a listing never returns. A prefix with a `.` or `..`
/// component starts from the root, as every listing did before.
fn list_root(base: &Path, prefix: &str) -> Option<PathBuf> {
    let dir = prefix.rfind('/').map_or("", |i| &prefix[..i]);
    if dir.is_empty()
        || dir
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Some(base.to_path_buf());
    }
    if dir.split('/').next() == Some(crate::validation::STAGING_DIR) {
        return None;
    }
    Some(base.join(dir))
}

/// Whether an I/O error on a key's path says there is no object there: the path does not
/// exist, or runs through a stored file (`raw/f.txt/x` while `raw/f.txt` is stored, ENOTDIR)
/// — a key an object store reports as missing.
fn is_missing(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// Opens the object stored at `path`, with its metadata. A directory is not an object: a
/// key whose path is a directory (`raw/a` while `raw/a/b` is stored, or left empty by
/// deletes) is `NotFound`, as an object store reports it, not an object of the directory's
/// size whose read then fails.
async fn open_object(path: &Path) -> Result<(fs::File, std::fs::Metadata)> {
    let file = fs::File::open(path).await.map_err(|e| {
        if is_missing(&e) {
            StorageError::NotFound
        } else {
            StorageError::Io(e)
        }
    })?;
    let meta = file.metadata().await?;
    if !meta.is_file() {
        return Err(StorageError::NotFound);
    }
    Ok((file, meta))
}

/// Marks the I/O error of a write the local store cannot hold because the name is taken
/// the other way round (see [`name_taken_on_disk`]). It rides inside `StorageError::Io`,
/// so callers that care (raw answers 409) can tell it from any other write failure, and
/// an object store, which holds both names, never produces it.
#[derive(Debug)]
pub(crate) struct NameTaken;

impl std::fmt::Display for NameTaken {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("the name is taken by another stored file or directory")
    }
}

impl std::error::Error for NameTaken {}

/// Whether the local store already uses the name of `path` (under the storage root `base`)
/// the other way round: a directory sits at `path` — with files under it or left empty by
/// deletes — or a file sits at one of its parent names, at any depth.
async fn name_taken_on_disk(base: &Path, path: &Path) -> bool {
    if fs::metadata(path).await.is_ok_and(|m| m.is_dir()) {
        return true;
    }
    for parent in path.ancestors().skip(1) {
        if parent == base || !parent.starts_with(base) {
            break;
        }
        if fs::metadata(parent).await.is_ok_and(|m| m.is_file()) {
            return true;
        }
    }
    false
}

/// The error of a write to `path` that failed with `e`: [`NameTaken`] when the name is
/// taken on disk, `e` as it was otherwise.
async fn write_failure(base: &Path, path: &Path, e: std::io::Error) -> StorageError {
    if name_taken_on_disk(base, path).await {
        StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            NameTaken,
        ))
    } else {
        StorageError::Io(e)
    }
}

/// Whether `path` is the staging directory of the storage root `base`.
fn is_staging_dir(path: &Path, base: &Path) -> bool {
    path.parent() == Some(base)
        && path.file_name() == Some(std::ffi::OsStr::new(crate::validation::STAGING_DIR))
}

fn create_tmp_sync(
    candidates: impl IntoIterator<Item = PathBuf>,
) -> std::io::Result<(TmpFileGuard, std::fs::File)> {
    for tmp in candidates {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(file) => return Ok((TmpFileGuard::new(tmp), file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("no free temp name after {TMP_CREATE_ATTEMPTS} attempts"),
    ))
}

/// Removes a write's temp file unless the write published it. The removal lives in
/// `Drop` because a write can stop at any `.await`: a SIGTERM ends `main`, and the
/// runtime it drops cancels every task still running, proxy-cache writes included.
/// Cleanup written after an `.await` never runs then, and the temp file stays beside
/// a real key for good. Removes exactly its own path, nothing that merely looks like
/// a temp file: a stored key may have that shape too.
struct TmpFileGuard {
    path: PathBuf,
    published: bool,
}

impl TmpFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// The temp file was renamed into place: nothing left to remove.
    fn published(mut self) {
        self.published = true;
    }
}

impl Drop for TmpFileGuard {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// fsync the parent directory of `path` so the directory entry written by a
/// just-completed `rename` is durable across power-loss. The file's own data is
/// fsync'd (`sync_all`) before the rename; the rename only becomes crash-durable
/// once the *parent directory* is also fsync'd. Without this, a power-loss after
/// `Ok` was returned can leave the file missing (or the old version) — violating
/// the "Ok implies durable" contract (L3 durability). Fails closed: a parent that
/// cannot be fsync'd means durability is not guaranteed, so we return Err.
async fn sync_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = fs::File::open(parent).await?;
        dir.sync_all().await?;
    }
    Ok(())
}

/// Local filesystem storage backend (zero-config default). Hash pins live in an
/// NDJSON sidecar next to the artifacts.
pub struct LocalStorage {
    base_path: PathBuf,
    pins: Arc<HashPinStore>,
    /// Per-key commit locks, see [`Self::commit_lock`].
    commit_locks: crate::PublishLocks,
    /// This instance's staging directory, see [`Staging`].
    staging: StagingCell,
}

impl LocalStorage {
    pub fn new(path: &str) -> Self {
        let base_path = PathBuf::from(path);
        let pins = Arc::new(HashPinStore::new(base_path.join(PIN_FILE)));
        Self {
            base_path,
            pins,
            commit_locks: Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new())),
            staging: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Serialize the two durable steps of a write to one key: publishing the body
    /// (the `rename`) and recording its hash pin (the NDJSON append).
    ///
    /// They are separate artifacts, so without this two writers of one key
    /// interleave into "body from A, last pin from B", and the next read fails
    /// hash-pin verification on bytes nobody tampered with — `INTEGRITY VIOLATION:
    /// refusing to serve tampered artifact` on a healthy object (#1041, surfaced by
    /// `nora migrate` on a Docker pull-through cache: 1 of 4039 keys). The object
    /// backends are unaffected, since there the pin travels in the object's own
    /// metadata, written in the same request as the body.
    ///
    /// The lock lives in the backend and not in a caller, so no future writer can
    /// reintroduce the split by forgetting to take `AppState::publish_lock` — which
    /// is exactly how the docker proxy-cache fill produced it.
    ///
    /// It narrows the crash window rather than closing it: a process that dies
    /// between the rename and the append still leaves the pair diverged, and an
    /// operator repairs that by rewriting the key (the body is intact, only the pin
    /// is stale).
    fn commit_lock(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        crate::acquire_publish_lock(&self.commit_locks, key)
    }

    /// Record `sha256` for `key`, on the blocking pool (the append is
    /// filesystem I/O). Fails closed: an artifact whose pin did not reach the
    /// disk would silently downgrade to open-world after the next restart — the
    /// #582/#604 bypass — so the write reports failure instead.
    ///
    /// On an immutable registry the client's retry hits the 409 guard and never
    /// re-runs this, so the orphaned body stays unpinned until an operator
    /// `repin`s it — still strictly better than a silent success.
    async fn record_pin(&self, key: &str, sha256: &str) -> Result<()> {
        let pins = Arc::clone(&self.pins);
        let key_owned = key.to_string();
        let hash = sha256.to_ascii_lowercase();
        tokio::task::spawn_blocking(move || pins.record_hash(&key_owned, &hash))
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
            .map_err(|e| {
                tracing::error!(error = %e, key = %key, "hash-pin record failed");
                StorageError::Io(std::io::Error::other(format!(
                    "hash-pin record failed: {e}"
                )))
            })
    }

    /// Drop the pin of `key`, for a write that stored bytes without a digest: the pin of the
    /// bytes it replaced must not outlive them (#1154). The object store gets this from the
    /// write itself, which replaces the object's attributes. A key without a pin writes nothing.
    /// Fails closed, as [`record_pin`](Self::record_pin) does: a stale pin left behind would
    /// fail every later read of the new bytes.
    async fn forget_pin(&self, key: &str) -> Result<()> {
        let pins = Arc::clone(&self.pins);
        let key_owned = key.to_string();
        tokio::task::spawn_blocking(move || pins.remove(&key_owned))
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
            .map_err(|e| {
                tracing::error!(error = %e, key = %key, "hash-pin tombstone failed");
                StorageError::Io(std::io::Error::other(format!(
                    "hash-pin tombstone failed: {e}"
                )))
            })
    }

    /// Create a new temp file for a write of `dest`, in this instance's staging
    /// directory (see [`Staging`]).
    #[cfg(test)]
    async fn create_tmp(&self, dest: &Path) -> Result<(TmpFileGuard, fs::File)> {
        self.create_tmp_in(dest, TmpPlace::Staging).await
    }

    /// Create a new temp file for a write of `dest` at `place`, under a name no file
    /// has yet.
    ///
    /// A name beside the key can be exactly a stored key's name (a raw upload
    /// `x.tmp.<pid>.<seq>`), and staging can hold anything a crash left. The file is
    /// therefore created exclusively (`O_EXCL`): a name that is taken is skipped for
    /// the next candidate, and an existing file is never opened, truncated or renamed
    /// away. The guard is armed only once the file is ours, so it can never remove
    /// somebody else's. The candidates' sequence numbers are drawn here, on the
    /// caller's thread; the staging directory is opened on the blocking pool.
    async fn create_tmp_in(
        &self,
        dest: &Path,
        place: TmpPlace,
    ) -> Result<(TmpFileGuard, fs::File)> {
        let seqs: Vec<u64> = (0..TMP_CREATE_ATTEMPTS).map(|_| next_tmp_seq()).collect();
        let cell = Arc::clone(&self.staging);
        let root = self.base_path.clone();
        let dest = dest.to_path_buf();
        // CANCEL-SAFETY: the file is created and its guard armed inside one blocking task,
        // and the guard travels in the task's output. If this future is dropped, tokio
        // drops that output with the JoinHandle or when the task completes, so the guard
        // still removes the file; a task not yet started at runtime shutdown never runs.
        let (guard, file) = tokio::task::spawn_blocking(move || {
            let staging = match place {
                TmpPlace::Staging => staging_dir_sync(&cell, &root),
                TmpPlace::BesideKey => None,
            };
            create_tmp_sync(seqs.into_iter().map(|seq| match staging {
                Some(dir) => dir.join(staging_tmp_name(seq)),
                None => tmp_path_with_seq(&dest, seq),
            }))
        })
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))?;
        Ok((guard, fs::File::from_std(file)))
    }

    /// Write `data` to a new temp file for `dest` at `place` and make it durable; the
    /// caller renames it into place.
    async fn write_tmp(&self, dest: &Path, data: &[u8], place: TmpPlace) -> Result<TmpFileGuard> {
        let (tmp, mut file) = self.create_tmp_in(dest, place).await?;
        file.write_all(data).await?;
        file.flush().await?;
        file.sync_all().await?;
        Ok(tmp)
    }

    /// Copy `src` to a new temp file for `dest` at `place` and make it durable; the
    /// caller renames it into place.
    async fn copy_to_tmp(&self, src: &Path, dest: &Path, place: TmpPlace) -> Result<TmpFileGuard> {
        let mut reader = fs::File::open(src).await?;
        let (tmp, mut writer) = self.create_tmp_in(dest, place).await?;
        let mut buf = vec![0u8; 8 * 1024 * 1024]; // 8 MiB chunks
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n]).await?;
        }
        writer.flush().await?;
        // Durability: fsync the copied data before publishing it. flush() only pushes
        // to the OS; sync_all() makes it crash-durable, matching the put() path (the
        // direct-rename branch relies on the caller having fsync'd src).
        writer.sync_all().await?;
        Ok(tmp)
    }

    /// This instance's staging directory, once a write has opened it.
    #[cfg(test)]
    fn staging_dir(&self) -> Option<PathBuf> {
        self.staging
            .get()
            .and_then(|staging| staging.as_ref())
            .map(|staging| staging.dir.clone())
    }

    fn key_to_path(&self, key: &str) -> PathBuf {
        self.base_path.join(key)
    }

    /// Recursively list all files under a directory (sync helper)
    fn list_files_sync(dir: &PathBuf, base: &PathBuf, prefix: &str, results: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(rel_path) = path.strip_prefix(base) {
                        let key = rel_path.to_string_lossy().replace('\\', "/");
                        if key != PIN_FILE
                            && !super::is_reserved_signing_key(&key)
                            && (key.starts_with(prefix) || prefix.is_empty())
                        {
                            results.push(key);
                        }
                    }
                } else if path.is_dir() && !is_staging_dir(&path, base) {
                    Self::list_files_sync(&path, base, prefix, results);
                }
            }
        }
    }

    /// Like [`Self::list_files_sync`] but also captures size/mtime from each
    /// file's metadata during the walk, so callers do not need a follow-up
    /// `stat()` per key (#738). Uses `std::fs::metadata` (symlink-following) to
    /// match the semantics of [`StorageBackend::stat`].
    fn list_files_with_meta_sync(
        dir: &PathBuf,
        base: &PathBuf,
        prefix: &str,
        results: &mut Vec<(String, FileMeta)>,
    ) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(metadata) = std::fs::metadata(&path) else {
                    continue;
                };
                if metadata.is_file() {
                    if let Ok(rel_path) = path.strip_prefix(base) {
                        let key = rel_path.to_string_lossy().replace('\\', "/");
                        if key != PIN_FILE
                            && !super::is_reserved_signing_key(&key)
                            && (key.starts_with(prefix) || prefix.is_empty())
                        {
                            let modified = metadata
                                .modified()
                                .ok()
                                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            results.push((
                                key,
                                FileMeta {
                                    size: metadata.len(),
                                    modified,
                                },
                            ));
                        }
                    }
                } else if metadata.is_dir() && !is_staging_dir(&path, base) {
                    Self::list_files_with_meta_sync(&path, base, prefix, results);
                }
            }
        }
    }
}

#[async_trait]
impl StorageBackend for LocalStorage {
    async fn put(&self, key: &str, data: &[u8], sha256: &str) -> Result<()> {
        let path = self.key_to_path(key);

        // Create parent directories
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent).await {
                return Err(write_failure(&self.base_path, &path, e).await);
            }
        }

        // Atomic write: write a temp file in staging, fsync, rename into place.
        // This prevents readers from seeing partial/truncated data during write.
        // Body and pin are published as one critical section (#1041, see commit_lock).
        let lock = self.commit_lock(key);
        let _commit = lock.lock().await;
        // CANCEL-SAFETY: the guard removes the temp file however the write ends —
        // error or cancellation at any `.await`, `create_tmp_in` included — until the
        // rename publishes it.
        let tmp = self.write_tmp(&path, data, TmpPlace::Staging).await?;
        let tmp = match fs::rename(tmp.path(), &path).await {
            Ok(()) => tmp,
            // The key's directory is on another filesystem than staging (a registry
            // directory mounted on its own): redo the write beside the key, where the
            // rename cannot cross. The staged copy goes with its guard.
            Err(e) if e.raw_os_error() == Some(EXDEV) => {
                drop(tmp);
                let beside = self.write_tmp(&path, data, TmpPlace::BesideKey).await?;
                if let Err(e) = fs::rename(beside.path(), &path).await {
                    return Err(write_failure(&self.base_path, &path, e).await);
                }
                beside
            }
            Err(e) => return Err(write_failure(&self.base_path, &path, e).await),
        };
        tmp.published();
        // Durability: make the rename's directory entry survive power-loss.
        sync_parent_dir(&path).await?;
        self.record_pin(key, sha256).await
    }

    async fn get(&self, key: &str) -> Result<(Bytes, Option<String>)> {
        let path = self.key_to_path(key);

        let (mut file, _) = open_object(&path).await?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;

        Ok((Bytes::from(buffer), self.pins.get(key)))
    }

    async fn pin(&self, key: &str) -> Option<String> {
        self.pins.get(key)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_to_path(key);
        // Body and pin leave as one critical section, as they arrive (#1041, see commit_lock):
        // a write of this key between the two steps would lose the pin it just recorded.
        let lock = self.commit_lock(key);
        let _commit = lock.lock().await;

        if let Err(e) = fs::remove_file(&path).await {
            // A directory is not an object; unlink(2) refuses it with EISDIR on Linux and
            // EPERM on macOS, so ask the path rather than the error.
            let is_dir = fs::metadata(&path).await.is_ok_and(|m| m.is_dir());
            return Err(if is_dir || is_missing(&e) {
                StorageError::NotFound
            } else {
                StorageError::Io(e)
            });
        }

        // A lost tombstone is fail-safe — a stale pin at worst yields a future
        // IntegrityViolation, healable via `repin` — so the delete still
        // reports success: the authoritative action (byte removal) is done.
        let pins = Arc::clone(&self.pins);
        let key_owned = key.to_string();
        if let Err(e) = tokio::task::spawn_blocking(move || pins.remove(&key_owned))
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
        {
            tracing::warn!(
                error = %e,
                key = %key,
                "hash-pin tombstone write failed; stale pin left (repin to heal)"
            );
        }

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let base = self.base_path.clone();
        let prefix = prefix.to_string();

        // Use blocking task for filesystem traversal
        tokio::task::spawn_blocking(move || {
            let mut results = Vec::new();
            if let Some(root) = list_root(&base, &prefix).filter(|r| r.exists()) {
                readable_listing_root(&root)?;
                Self::list_files_sync(&root, &base, &prefix, &mut results);
            }
            results.sort();
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Io(std::io::Error::other(format!("list task panicked: {e}"))))?
    }

    async fn list_with_meta(&self, prefix: &str) -> Result<Vec<(String, FileMeta)>> {
        let base = self.base_path.clone();
        let prefix = prefix.to_string();

        tokio::task::spawn_blocking(move || {
            let mut results = Vec::new();
            if let Some(root) = list_root(&base, &prefix).filter(|r| r.exists()) {
                readable_listing_root(&root)?;
                Self::list_files_with_meta_sync(&root, &base, &prefix, &mut results);
            }
            results.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::Io(std::io::Error::other(format!("list task panicked: {e}"))))?
    }

    async fn stat(&self, key: &str) -> Option<FileMeta> {
        let path = self.key_to_path(key);
        let metadata = fs::metadata(&path).await.ok().filter(|m| m.is_file())?;
        let modified = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        Some(FileMeta {
            size: metadata.len(),
            modified,
        })
    }

    async fn health_check(&self) -> bool {
        // A real write-probe — `base_path.exists()` is not a health signal: a
        // read-only mount or a full disk where the directory already exists would
        // still report healthy. Create + write + fsync + remove a unique temp
        // file; only a genuinely writable backing store passes.
        if fs::create_dir_all(&self.base_path).await.is_err() {
            return false;
        }
        let seq = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let probe =
            self.base_path
                .join(format!(".nora-health-probe.{}.{}", std::process::id(), seq));
        let writable = match fs::File::create(&probe).await {
            Ok(mut file) => file.write_all(b"ok").await.is_ok() && file.sync_all().await.is_ok(),
            Err(_) => false,
        };
        let _ = fs::remove_file(&probe).await; // best-effort cleanup
        writable
    }

    async fn total_size(&self) -> u64 {
        let base = self.base_path.clone();
        tokio::task::spawn_blocking(move || {
            fn dir_size(path: &std::path::Path, is_root: bool) -> u64 {
                let mut total = 0u64;
                if let Ok(entries) = std::fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if is_root && path.file_name().is_some_and(|n| n == PIN_FILE) {
                                continue;
                            }
                            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                        } else if path.is_dir() {
                            // `<root>/tmp/` holds in-flight streamed uploads —
                            // transient staging, not stored artifacts; counting
                            // it makes the storage gauge sawtooth during pushes.
                            if is_root && path.file_name().is_some_and(|n| n == "tmp") {
                                continue;
                            }
                            // Writes in progress, see `Staging`.
                            if is_root
                                && path
                                    .file_name()
                                    .is_some_and(|n| n == crate::validation::STAGING_DIR)
                            {
                                continue;
                            }
                            total += dir_size(&path, false);
                        }
                    }
                }
                total
            }
            dir_size(&base, true)
        })
        .await
        .unwrap_or(0)
    }

    fn backend_name(&self) -> &'static str {
        "local"
    }

    async fn prepare(&self) {
        let cell = Arc::clone(&self.staging);
        let root = self.base_path.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            staging_dir_sync(&cell, &root);
        })
        .await
        {
            tracing::warn!(error = %e, "Opening the staging directory failed");
        }
    }

    async fn put_from_path(&self, key: &str, src: &Path, sha256: Option<&str>) -> Result<()> {
        let dest = self.key_to_path(key);
        if let Some(parent) = dest.parent() {
            if let Err(e) = fs::create_dir_all(parent).await {
                return Err(write_failure(&self.base_path, &dest, e).await);
            }
        }
        // Body and pin are published as one critical section (#1041, see commit_lock).
        let lock = self.commit_lock(key);
        let _commit = lock.lock().await;
        // Try atomic rename first; fall back to streaming copy on EXDEV
        // (cross-device link — src and dest on different filesystems).
        match fs::rename(src, &dest).await {
            Ok(()) => {
                // Durability: make the rename's directory entry survive power-loss.
                sync_parent_dir(&dest).await?;
            }
            Err(e) if e.raw_os_error() == Some(EXDEV) => {
                // Each writer stages its own copy: two fills of one blob must not share
                // (and truncate, and rename away) one temp file.
                // CANCEL-SAFETY: as in put(), the guard removes the temp file on error
                // or cancellation until the rename publishes it.
                let tmp = self.copy_to_tmp(src, &dest, TmpPlace::Staging).await?;
                let tmp = match fs::rename(tmp.path(), &dest).await {
                    Ok(()) => tmp,
                    // dest is on another filesystem than staging too: copy beside it.
                    Err(e) if e.raw_os_error() == Some(EXDEV) => {
                        drop(tmp);
                        let beside = self.copy_to_tmp(src, &dest, TmpPlace::BesideKey).await?;
                        if let Err(e) = fs::rename(beside.path(), &dest).await {
                            return Err(write_failure(&self.base_path, &dest, e).await);
                        }
                        beside
                    }
                    Err(e) => return Err(write_failure(&self.base_path, &dest, e).await),
                };
                tmp.published();
                // Durability: make the rename's directory entry durable.
                sync_parent_dir(&dest).await?;
                let _ = fs::remove_file(src).await;
            }
            Err(e) => return Err(write_failure(&self.base_path, &dest, e).await),
        }
        match sha256 {
            Some(hash) => self.record_pin(key, hash).await,
            None => self.forget_pin(key).await,
        }
    }

    async fn copy(&self, src: &str, dst: &str, sha256: Option<&str>) -> Result<()> {
        let src_path = self.key_to_path(src);
        let dst_path = self.key_to_path(dst);
        // A directory is not an object (see `open_object`).
        if fs::metadata(&src_path).await.is_ok_and(|m| m.is_dir()) {
            return Err(StorageError::NotFound);
        }
        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        // Body and pin are published as one critical section (#1041, see commit_lock).
        let lock = self.commit_lock(dst);
        let _commit = lock.lock().await;
        // Hard link: the two keys share one inode, so a mounted blob costs no
        // extra bytes and cannot drift from its source.
        let linked = match fs::hard_link(&src_path, &dst_path).await {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&dst_path).await?;
                fs::hard_link(&src_path, &dst_path).await
            }
            other => other,
        };
        match linked {
            Ok(()) => {
                // A hard link shares the source inode and thus its mtime; a freshly
                // published object must look fresh so GC's grace window covers an
                // in-flight mount whose referencing manifest lands next (the
                // byte-copy fallback below gets a current mtime from the new file,
                // and S3 copy stamps a current LastModified). Sharing the inode means
                // this also refreshes the source's mtime, which can only defer the
                // source's own grace-based collection (fail-safe), never delete early.
                // Best-effort: a failed stamp only leaves the old mtime — never fail
                // the mount for it.
                let touch = dst_path.clone();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    std::fs::File::open(&touch)
                        .and_then(|f| f.set_modified(std::time::SystemTime::now()))
                })
                .await
                .map_err(std::io::Error::other)
                .and_then(|inner| inner)
                {
                    tracing::warn!(dst = %dst, error = %e, "copy: could not refresh mtime of linked object");
                }
                sync_parent_dir(&dst_path).await?;
            }
            Err(e) if is_missing(&e) => return Err(StorageError::NotFound),
            // Cross-device, or a filesystem without links — copy the bytes.
            Err(_) => {
                fs::copy(&src_path, &dst_path).await.map_err(|e| {
                    if is_missing(&e) {
                        StorageError::NotFound
                    } else {
                        StorageError::Io(e)
                    }
                })?;
                sync_parent_dir(&dst_path).await?;
            }
        }
        match sha256
            .map(str::to_ascii_lowercase)
            .or_else(|| self.pins.get(src))
        {
            Some(hash) => self.record_pin(dst, &hash).await,
            None => self.forget_pin(dst).await,
        }
    }

    async fn get_reader(
        &self,
        key: &str,
    ) -> Result<(u64, Option<String>, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        let path = self.key_to_path(key);
        let (file, meta) = open_object(&path).await?;
        Ok((meta.len(), self.pins.get(key), Box::pin(file)))
    }

    async fn get_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<(u64, Pin<Box<dyn AsyncRead + Send + Unpin>>)> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let path = self.key_to_path(key);
        let (mut file, meta) = open_object(&path).await?;
        let size = meta.len();
        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start)).await?;
        }
        let len = end.saturating_sub(start) + 1;
        Ok((size, Box::pin(file.take(len))))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn a_listing_starts_at_the_directory_its_prefix_names() {
        let base = std::path::Path::new("/s");
        let root = |p: &str| super::list_root(base, p);
        assert_eq!(root(""), Some(base.to_path_buf()));
        assert_eq!(root("raw"), Some(base.to_path_buf()));
        assert_eq!(root("npm/"), Some(base.join("npm")));
        assert_eq!(root("npm/pkg"), Some(base.join("npm")));
        assert_eq!(
            root("npm/pkg/versions/"),
            Some(base.join("npm/pkg/versions"))
        );
        assert_eq!(
            root("npm/@s/pkg/versions/"),
            Some(base.join("npm/@s/pkg/versions"))
        );
        assert_eq!(root(".nora-staging/x/"), None);
        assert_eq!(root("npm/../raw/"), Some(base.to_path_buf()));
        assert_eq!(root("npm//x"), Some(base.to_path_buf()));
    }

    /// Starting the walk at the prefix's directory returns exactly what the full walk did.
    #[tokio::test]
    async fn a_prefix_listing_returns_what_the_full_walk_returned() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        for key in [
            "npm/pkg/versions/1.0.0.json",
            "npm/pkg/versions/2.0.0.json",
            "npm/pkg/metadata.json",
            "npm/pkgx/versions/1.0.0.json",
            "npm/@s/pkg/versions/1.0.0.json",
            "raw/a/b.txt",
            "rawx/c.txt",
        ] {
            use sha2::Digest as _;
            let sha = hex::encode(sha2::Sha256::digest(b"x"));
            storage.put(key, b"x", &sha).await.unwrap();
        }
        std::fs::create_dir_all(dir.path().join(crate::validation::STAGING_DIR).join("i")).unwrap();
        std::fs::write(
            dir.path().join(crate::validation::STAGING_DIR).join("i/t"),
            b"x",
        )
        .unwrap();
        std::fs::write(dir.path().join(super::PIN_FILE), b"{}").unwrap();
        let full = |prefix: &str| {
            let mut out = Vec::new();
            LocalStorage::list_files_sync(
                &dir.path().to_path_buf(),
                &dir.path().to_path_buf(),
                prefix,
                &mut out,
            );
            out.sort();
            out
        };
        for prefix in [
            "",
            "npm/",
            "npm/pkg",
            "npm/pkg/",
            "npm/pkg/versions/",
            "npm/@s/pkg/versions/",
            "raw",
            "raw/",
            "raw/a/b.txt",
            "missing/",
            ".nora-staging/",
            ".nora-staging/i/",
            "npm/../raw/",
        ] {
            assert_eq!(
                storage.list(prefix).await.unwrap(),
                full(prefix),
                "list {prefix:?}"
            );
            let with_meta: Vec<String> = storage
                .list_with_meta(prefix)
                .await
                .unwrap()
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            assert_eq!(with_meta, full(prefix), "list_with_meta {prefix:?}");
        }
    }

    use super::*;

    /// Both write paths mark a taken name — a directory at the key, a file at a parent name
    /// at any depth — and the mark is what tells it from any other write failure.
    #[tokio::test]
    async fn both_write_paths_mark_a_taken_name() {
        let is_marked = |e: &StorageError| matches!(e, StorageError::Io(io) if io.get_ref().is_some_and(|inner| inner.is::<NameTaken>()));
        let dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let sha = hex::encode(Sha256::digest(b"x"));
        for key in ["raw/dir/f.txt", "raw/file.txt"] {
            storage.put(key, b"x", &sha).await.unwrap();
        }
        for key in ["raw/dir", "raw/file.txt/x", "raw/file.txt/a/b"] {
            let err = storage.put(key, b"x", &sha).await.unwrap_err();
            assert!(is_marked(&err), "put {key}: {err}");
            let src = dir.path().join("upload.tmp");
            std::fs::write(&src, b"x").unwrap();
            let err = storage
                .put_from_path(key, &src, Some(&sha))
                .await
                .unwrap_err();
            assert!(is_marked(&err), "put_from_path {key}: {err}");
        }
        // A fresh name is written, unmarked.
        storage.put("raw/new/f.txt", b"x", &sha).await.unwrap();
    }

    /// A name is taken by a directory at it — with files under it or emptied by a delete —
    /// or by a file at any parent name; never by a neighbour sharing its first characters,
    /// a fresh name, or a name under a directory.
    #[tokio::test]
    async fn a_name_is_taken_by_a_directory_at_it_or_a_file_above_it() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let storage = LocalStorage::new(base.to_str().unwrap());
        for key in ["raw/dir/f.txt", "raw/file.txt", "raw/e/f.txt"] {
            let sha = hex::encode(Sha256::digest(b"x"));
            storage.put(key, b"x", &sha).await.unwrap();
        }
        storage.delete("raw/e/f.txt").await.unwrap();
        for (key, taken) in [
            ("raw/dir", true),
            ("raw/e", true),
            ("raw/file.txt/x", true),
            ("raw/file.txt/a/b/x", true),
            ("raw/dirx", false),
            ("raw/file", false),
            ("raw/file.txt.bak/x", false),
            ("raw/new/x", false),
            ("raw/dir/new", false),
        ] {
            assert_eq!(
                name_taken_on_disk(base, &base.join(key)).await,
                taken,
                "{key}"
            );
        }
    }
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    thread_local! {
        /// Pins the sequence numbers of the next temp names taken on this thread, so a
        /// test can know a write's temp name in advance. Tests on other threads keep
        /// the shared counter.
        pub(super) static NEXT_TMP_SEQ: std::cell::Cell<Option<u64>> =
            const { std::cell::Cell::new(None) };
    }

    /// The temp name of `key`'s write with sequence number `seq`, as a storage key.
    fn tmp_key(key: &str, seq: u64) -> String {
        let (dir, name) = key.rsplit_once('/').unwrap();
        let tmp = tmp_path_with_seq(Path::new(name), seq);
        format!("{dir}/{}", tmp.to_string_lossy())
    }

    /// A stored key may be named exactly like the temp file a later write of another
    /// key picks (`raw/report.tmp.<pid>.<seq>` is a valid raw upload). The write must
    /// take the next free name and leave the stored key as it was — neither truncated
    /// and renamed over the new key, nor removed by the temp-file guard.
    #[tokio::test]
    async fn put_never_reuses_a_stored_key_named_like_its_temp_file() {
        let dir = TempDir::new().unwrap();
        // The temp name beside the key is the fallback path (no staging directory).
        block_staging(dir.path());
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let seq = 9_000_000;
        let stored = tmp_key("raw/report", seq);
        put(&storage, &stored, b"stored bytes").await.unwrap();

        NEXT_TMP_SEQ.with(|next| next.set(Some(seq)));
        put(&storage, "raw/report", b"new body").await.unwrap();
        NEXT_TMP_SEQ.with(|next| next.set(None));

        assert_eq!(&get(&storage, &stored).await.unwrap()[..], b"stored bytes");
        assert_eq!(&get(&storage, "raw/report").await.unwrap()[..], b"new body");
        let leftovers = tmp_leftovers(dir.path());
        assert_eq!(leftovers.len(), 1, "only the stored key: {leftovers:?}");
    }

    /// The retry is bounded: when every candidate name is taken, the write fails and
    /// every stored key is untouched.
    #[tokio::test]
    async fn put_gives_up_after_bounded_temp_name_collisions() {
        let dir = TempDir::new().unwrap();
        // The temp name beside the key is the fallback path (no staging directory).
        block_staging(dir.path());
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let seq = 9_100_000;
        let stored: Vec<String> = (0..u64::from(TMP_CREATE_ATTEMPTS))
            .map(|i| tmp_key("raw/report", seq + i))
            .collect();
        for key in &stored {
            put(&storage, key, key.as_bytes()).await.unwrap();
        }

        NEXT_TMP_SEQ.with(|next| next.set(Some(seq)));
        let result = put(&storage, "raw/report", b"new body").await;
        NEXT_TMP_SEQ.with(|next| next.set(None));

        assert!(
            result.is_err(),
            "every temp name is taken: the write must fail"
        );
        assert!(get(&storage, "raw/report").await.is_err());
        for key in &stored {
            assert_eq!(&get(&storage, key).await.unwrap()[..], key.as_bytes());
        }
    }

    /// The backend pins what it stores, so every test write carries the digest
    /// of its own bytes.
    async fn put(storage: &LocalStorage, key: &str, data: &[u8]) -> Result<()> {
        storage
            .put(key, data, &hex::encode(Sha256::digest(data)))
            .await
    }

    async fn get(storage: &LocalStorage, key: &str) -> Result<Bytes> {
        storage.get(key).await.map(|(data, _pin)| data)
    }

    /// #1041: the body and its hash pin are two separate durable artifacts, so two
    /// writers of one key must never leave "body from one, last pin from the other"
    /// behind — the next read then fails hash-pin verification on bytes nobody
    /// tampered with (`INTEGRITY VIOLATION` on a healthy object, which is how this
    /// was found: one key out of 4039 during `nora migrate`). The guarantee is
    /// structural (the per-key commit lock in the backend); this hammers the pair and
    /// checks after every round that the recorded pin describes the stored body.
    /// A delete removes the body and then its pin. A write of the same key that lands between the
    /// two would lose the pin it just recorded: the stored copy is then unpinned, so a reader that
    /// needs a pin fetches it again, and a reader that does not serves it unchecked. The delete
    /// therefore holds the key's commit lock across both steps, as a write does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_delete_holds_the_commit_lock_across_body_and_pin() {
        let dir = TempDir::new().unwrap();
        let storage = Arc::new(LocalStorage::new(dir.path().to_str().unwrap()));
        let key = "hf/models/org/model/blobs/aaaa";
        put(&storage, key, b"first").await.unwrap();

        let lock = storage.commit_lock(key);
        let held = lock.lock().await;
        let deleting = tokio::spawn({
            let storage = Arc::clone(&storage);
            async move { storage.delete(key).await }
        });
        // CANCEL-SAFETY: the timeout only stops waiting for the spawned delete; the task itself
        // keeps running and is awaited below.
        let early = tokio::time::timeout(std::time::Duration::from_millis(300), async {
            while storage.stat(key).await.is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            early.is_err(),
            "the delete removed the body while a write held the key"
        );
        drop(held);
        deleting.await.unwrap().unwrap();
        assert!(storage.stat(key).await.is_none());
        assert_eq!(storage.pins.get(key), None, "the pin outlived its body");

        // A write after the delete keeps its pin.
        put(&storage, key, b"second").await.unwrap();
        assert_eq!(
            storage.pins.get(key).as_deref(),
            Some(hex::encode(Sha256::digest(b"second")).as_str())
        );
    }

    /// A listing whose own directory cannot be read is an error, not "nothing here"; a directory
    /// deeper down that cannot be read is still skipped. (Root reads anything: then it is moot.)
    #[tokio::test]
    async fn an_unreadable_listing_directory_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        put(&storage, "npm/pkg/versions/1.0.0.json", b"{}")
            .await
            .unwrap();
        put(&storage, "npm/pkg/tarballs/pkg-1.0.0.tgz", b"tgz")
            .await
            .unwrap();
        let versions = dir.path().join("npm/pkg/versions");
        std::fs::set_permissions(&versions, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = std::fs::read_dir(&versions).is_err();
        let own = storage.list("npm/pkg/versions/").await;
        let meta = storage.list_with_meta("npm/pkg/versions/").await;
        let wider = storage.list("npm/pkg/").await;
        std::fs::set_permissions(&versions, std::fs::Permissions::from_mode(0o755)).unwrap();
        if unreadable {
            assert!(own.is_err(), "{own:?}");
            assert!(meta.is_err());
            assert_eq!(
                wider.unwrap(),
                vec!["npm/pkg/tarballs/pkg-1.0.0.tgz".to_string()]
            );
        }
        assert!(storage
            .list("npm/absent/versions/")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_writers_never_split_body_from_pin() {
        let dir = TempDir::new().unwrap();
        let storage = Arc::new(LocalStorage::new(dir.path().to_str().unwrap()));
        let key = "docker/docker.io/library/alpine/manifests/sha256:feedface.meta.json";

        for round in 0..40 {
            let a = format!(r#"{{"downloads":{round},"writer":"a"}}"#).into_bytes();
            let b = format!(r#"{{"downloads":{round},"writer":"b","pad":"xx"}}"#).into_bytes();
            let (sa, sb) = (Arc::clone(&storage), Arc::clone(&storage));
            let (ka, kb) = (key.to_string(), key.to_string());
            let wa = tokio::spawn(async move { put(&sa, &ka, &a).await });
            let wb = tokio::spawn(async move { put(&sb, &kb, &b).await });
            wa.await.unwrap().unwrap();
            wb.await.unwrap().unwrap();

            let (body, pin) = storage.get(key).await.unwrap();
            let stored = hex::encode(Sha256::digest(&body));
            assert_eq!(
                pin.as_deref(),
                Some(stored.as_str()),
                "round {round}: the recorded pin does not describe the stored body — \
                 a reader would see INTEGRITY VIOLATION on untampered bytes"
            );
        }
    }

    /// `put_from_path` across filesystems (EXDEV: the spool on tmpfs, storage on disk)
    /// copies through a temp file. Concurrent writes of one key — two proxy fills of the
    /// same blob — must each succeed, never publish a torn blob to a reader, and leave
    /// no temp file behind. Skipped where no second filesystem is available.
    #[tokio::test]
    async fn concurrent_cross_device_put_from_path_is_atomic() {
        use std::os::unix::fs::MetadataExt;
        let Ok(src_dir) = TempDir::new_in("/dev/shm") else {
            eprintln!("skip: /dev/shm unavailable, cannot force EXDEV");
            return;
        };
        let store_dir = TempDir::new().unwrap();
        let (a, b) = (
            std::fs::metadata(src_dir.path()).unwrap().dev(),
            std::fs::metadata(store_dir.path()).unwrap().dev(),
        );
        if a == b {
            eprintln!("skip: /dev/shm and the temp dir share a filesystem, no EXDEV");
            return;
        }
        let storage = Arc::new(LocalStorage::new(store_dir.path().to_str().unwrap()));
        let data: Arc<Vec<u8>> =
            Arc::new((0..8 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect());
        let key = "docker/library/test/blobs/sha256:same";
        let dest = storage.key_to_path(key);

        let (reader_dest, reader_data) = (dest.clone(), Arc::clone(&data));
        let reader = tokio::spawn({
            let (dest, data) = (reader_dest, reader_data);
            async move {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                while std::time::Instant::now() < deadline {
                    if let Ok(seen) = tokio::fs::read(&dest).await {
                        assert_eq!(seen.len(), data.len(), "a reader saw a torn blob");
                    }
                    tokio::task::yield_now().await;
                }
            }
        });
        let mut writers = Vec::new();
        for i in 0..8 {
            let src = src_dir.path().join(format!("spool-{i}"));
            std::fs::write(&src, data.as_slice()).unwrap();
            let storage = Arc::clone(&storage);
            let handle = tokio::spawn(async move { storage.put_from_path(key, &src, None).await });
            writers.push(handle);
        }
        for writer in writers {
            writer
                .await
                .unwrap()
                .expect("every concurrent write succeeds");
        }
        reader.await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), *data);
        let leftovers: Vec<_> = std::fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    /// Temp files (`<name>.tmp.<pid>.<seq>`) under `dir`, recursively.
    /// Temp files under the storage root `dir`: `<name>.tmp.<pid>.<seq>` beside a
    /// key, and every file in the staging directory except an instance's lock.
    fn tmp_leftovers(dir: &Path) -> Vec<String> {
        let staging = dir.join(crate::validation::STAGING_DIR);
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.to_string_lossy().contains(".tmp.")
                    || (path.starts_with(&staging)
                        && path != staging
                        && entry.file_name() != STAGING_LOCK_FILE)
                {
                    found.push(path.to_string_lossy().into_owned());
                }
            }
        }
        found
    }

    /// Make the staging directory impossible to create (a plain file has its name),
    /// so writes fall back to a temp file beside the key.
    fn block_staging(dir: &Path) {
        std::fs::write(dir.join(crate::validation::STAGING_DIR), b"").unwrap();
    }

    /// Spawn four 8 MiB writes on a multi-thread runtime, wait until one of them
    /// has a temp file on disk, and drop the runtime — what the end of `main` does
    /// after a SIGTERM. Returns whether a write was caught mid-way. `stored` is the
    /// number of stored keys under `dir` that already look like temp files.
    fn drop_runtime_mid_write(
        storage: &Arc<LocalStorage>,
        dir: &Path,
        round: u32,
        stored: usize,
    ) -> Vec<String> {
        let data: Arc<Vec<u8>> = Arc::new(vec![0x5a; 8 << 20]);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        for i in 0..4 {
            let (storage, data) = (Arc::clone(storage), Arc::clone(&data));
            let key = format!("npm/pkg{i}/-/pkg{i}-1.0.{round}.tgz");
            rt.spawn(async move { put(&storage, &key, &data).await });
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while tmp_leftovers(dir).len() <= stored && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        let seen = tmp_leftovers(dir);
        drop(rt);
        if seen.len() > stored {
            seen
        } else {
            Vec::new()
        }
    }

    /// A SIGTERM ends `main`, and the runtime it drops cancels every task still
    /// running — including the proxy-cache writes spawned after a fetch. A cancelled
    /// write must not leave its temp file behind: each one is a stray `*.tmp.*`
    /// beside a real key, and nothing removes it later. A round in which no write
    /// was caught mid-way does not count, so the test cannot pass without having
    /// exercised the cancellation.
    #[test]
    fn cancelled_put_leaves_no_temp_file() {
        let mut caught_mid_write = 0;
        for round in 0..5 {
            let dir = TempDir::new().unwrap();
            let storage = Arc::new(LocalStorage::new(dir.path().to_str().unwrap()));
            if !drop_runtime_mid_write(&storage, dir.path(), round, 0).is_empty() {
                caught_mid_write += 1;
            }
            let leftovers = tmp_leftovers(dir.path());
            assert!(
                leftovers.is_empty(),
                "round {round}: a cancelled write left its temp file behind: {leftovers:?}"
            );
        }
        assert!(
            caught_mid_write > 0,
            "no round caught a write mid-way, so cancellation was never exercised"
        );
    }

    /// The other side of the cleanup: a stored key that merely looks like a temp
    /// file (a raw upload may be named `x.tmp.1.2`) is never removed — not by the
    /// cancelled writes beside it, and not by opening the storage again.
    #[test]
    fn stored_key_shaped_like_a_temp_file_survives_cancelled_writes_and_restart() {
        let dir = TempDir::new().unwrap();
        let storage = Arc::new(LocalStorage::new(dir.path().to_str().unwrap()));
        let keys: Vec<String> = (0..4)
            .map(|i| format!("npm/pkg{i}/-/pkg{i}-1.0.0.tmp.1.2"))
            .chain(["raw/report.tmp.1.2".to_string()])
            .collect();
        let rt = tokio::runtime::Runtime::new().unwrap();
        for key in &keys {
            rt.block_on(put(&storage, key, key.as_bytes())).unwrap();
        }
        drop(rt);

        assert!(
            !drop_runtime_mid_write(&storage, dir.path(), 0, keys.len()).is_empty(),
            "the writes must be caught mid-way for this to test anything"
        );

        let reopened = LocalStorage::new(dir.path().to_str().unwrap());
        let rt = tokio::runtime::Runtime::new().unwrap();
        for key in &keys {
            let body = rt
                .block_on(get(&reopened, key))
                .unwrap_or_else(|e| panic!("stored key {key} is gone: {e:?}"));
            assert_eq!(&body[..], key.as_bytes());
        }
    }

    // --- E: staging directory ---

    /// A write in progress lives in this instance's staging directory, never beside
    /// the key it is writing: after a crash a file beside a key looks like a key.
    #[test]
    fn in_flight_write_is_staged_not_beside_its_key() {
        for round in 0..5 {
            let dir = TempDir::new().unwrap();
            let storage = Arc::new(LocalStorage::new(dir.path().to_str().unwrap()));
            let seen = drop_runtime_mid_write(&storage, dir.path(), round, 0);
            if seen.is_empty() {
                continue;
            }
            let staging = dir.path().join(crate::validation::STAGING_DIR);
            for path in &seen {
                assert!(
                    Path::new(path).starts_with(&staging),
                    "a write in progress outside the staging directory: {path}"
                );
            }
            return;
        }
        panic!("no round caught a write mid-way");
    }

    /// Take a temp file from `storage` as a write would, and keep it: the returned
    /// path stays on disk until the guard drops.
    fn take_tmp(rt: &tokio::runtime::Runtime, storage: &LocalStorage) -> TmpFileGuard {
        let dest = storage.key_to_path("npm/pkg/-/pkg-1.0.0.tgz");
        let (guard, _file) = rt.block_on(storage.create_tmp(&dest)).unwrap();
        guard
    }

    /// SIGKILL, OOM or a power cut: the instance's temp file stays, its guard never
    /// ran. The instance's lock went with its file descriptors, so the next instance
    /// to open the staging directory removes what the dead one left.
    #[test]
    fn a_new_instance_removes_the_staging_of_a_dead_one() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_str().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let dead = LocalStorage::new(root);
        let orphan = take_tmp(&rt, &dead);
        let orphan_path = orphan.path().to_path_buf();
        std::mem::forget(orphan);
        let dead_dir = dead
            .staging_dir()
            .expect("a write opens the staging directory");
        assert!(orphan_path.starts_with(&dead_dir));
        drop(dead);
        assert!(orphan_path.exists(), "nothing removed it yet");

        let next = LocalStorage::new(root);
        rt.block_on(put(&next, "npm/other/-/other-1.0.0.tgz", b"x"))
            .unwrap();
        assert!(
            !orphan_path.exists(),
            "the dead instance's temp file is still there"
        );
        assert!(
            !dead_dir.exists(),
            "the dead instance's staging directory is still there"
        );
    }

    /// A staging directory under its final name without a lock file was being removed
    /// when its remover died: no live instance owns it.
    #[test]
    fn a_staging_directory_without_a_lock_is_removed() {
        let dir = TempDir::new().unwrap();
        let lockless = dir
            .path()
            .join(crate::validation::STAGING_DIR)
            .join("0123456789abcdef");
        std::fs::create_dir_all(&lockless).unwrap();
        std::fs::write(lockless.join("7.tmp"), b"left").unwrap();

        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(storage.prepare());
        assert!(!lockless.exists());
    }

    /// The removal happens at start, not only at the first write after it: a server
    /// that restarts and only serves reads still clears the dead instance's files.
    #[test]
    fn start_removes_the_staging_of_a_dead_instance_without_a_write() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_str().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let dead = LocalStorage::new(root);
        let orphan = take_tmp(&rt, &dead);
        let orphan_path = orphan.path().to_path_buf();
        std::mem::forget(orphan);
        drop(dead);

        let next = LocalStorage::new(root);
        rt.block_on(next.prepare());
        assert!(
            !orphan_path.exists(),
            "start left the dead instance's temp file"
        );
        assert!(
            next.staging_dir().is_some(),
            "start opens this instance's staging"
        );
    }

    /// The other side: during a rolling update two instances share the volume. The
    /// new one must leave the old one's write in progress alone, and a stored key
    /// shaped like a temp file is never staging at all.
    #[test]
    fn a_new_instance_keeps_the_staging_of_a_live_one() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_str().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let live = LocalStorage::new(root);
        rt.block_on(put(&live, "raw/report.tmp.1.2", b"stored"))
            .unwrap();
        let in_flight = take_tmp(&rt, &live);
        let live_dir = live.staging_dir().unwrap();

        let next = LocalStorage::new(root);
        rt.block_on(put(&next, "npm/other/-/other-1.0.0.tgz", b"x"))
            .unwrap();
        assert!(
            in_flight.path().exists(),
            "the live instance's write was removed"
        );
        assert!(live_dir.exists());
        assert_ne!(next.staging_dir().unwrap(), live_dir);
        assert_eq!(
            &rt.block_on(get(&next, "raw/report.tmp.1.2")).unwrap()[..],
            b"stored"
        );

        let path = in_flight.path().to_path_buf();
        drop(in_flight);
        assert!(
            !path.exists(),
            "the guard still removes its own file at once"
        );
    }

    /// A staging directory caught half-created (`.new-*`, before its rename) is
    /// removed once it is old enough that no instance can still be creating it.
    #[test]
    fn a_half_created_staging_directory_is_removed_only_when_stale() {
        let dir = TempDir::new().unwrap();
        let staging = dir.path().join(crate::validation::STAGING_DIR);
        let old = staging.join(format!("{STAGING_NEW_PREFIX}old"));
        let young = staging.join(format!("{STAGING_NEW_PREFIX}young"));
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&young).unwrap();
        let long_ago = std::time::SystemTime::now() - STAGING_NEW_MAX_AGE * 2;
        std::fs::File::open(&old)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();

        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(put(&storage, "raw/a", b"a")).unwrap();
        assert!(!old.exists(), "a stale half-created directory stays");
        assert!(
            young.exists(),
            "a directory still being created was removed"
        );
    }

    /// Staging is storage bookkeeping, not an artifact: it is left out of the size
    /// gauge and of the backend's own listings, by its directory and not by a name
    /// pattern.
    #[tokio::test]
    async fn staging_is_left_out_of_size_and_listings() {
        let dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        put(&storage, "raw/a", b"abc").await.unwrap();
        let dest = storage.key_to_path("raw/b");
        let (in_flight, mut file) = storage.create_tmp(&dest).await.unwrap();
        file.write_all(&[0u8; 1000]).await.unwrap();
        file.flush().await.unwrap();
        assert!(in_flight.path().exists());

        assert_eq!(storage.total_size().await, 3);
        assert_eq!(storage.list("").await.unwrap(), vec!["raw/a".to_string()]);
        let listed: Vec<String> = storage
            .list_with_meta("")
            .await
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(listed, vec!["raw/a".to_string()]);
    }

    /// A taken name in staging is skipped like one beside a key, the retry is
    /// bounded, and an existing file there is never touched.
    #[tokio::test]
    async fn staging_skips_taken_names_and_gives_up_after_the_bound() {
        let dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        put(&storage, "raw/first", b"1").await.unwrap();
        let staging = storage.staging_dir().unwrap();
        let seq = 9_200_000;
        let taken: Vec<PathBuf> = (0..u64::from(TMP_CREATE_ATTEMPTS))
            .map(|i| staging.join(staging_tmp_name(seq + i)))
            .collect();
        for path in &taken {
            std::fs::write(path, b"someone else's").unwrap();
        }

        NEXT_TMP_SEQ.with(|next| next.set(Some(seq)));
        let all_taken = put(&storage, "raw/report", b"new body").await;
        NEXT_TMP_SEQ.with(|next| next.set(Some(seq + 2)));
        let some_free = put(&storage, "raw/report", b"new body").await;
        NEXT_TMP_SEQ.with(|next| next.set(None));

        assert!(
            all_taken.is_err(),
            "every staging name is taken: the write must fail"
        );
        some_free.expect("a free name after two taken ones");
        assert_eq!(&get(&storage, "raw/report").await.unwrap()[..], b"new body");
        for path in &taken {
            assert_eq!(std::fs::read(path).unwrap(), b"someone else's");
        }
    }

    /// When a key's directory sits on another filesystem than the storage root (a
    /// registry directory mounted separately), the rename out of staging fails with
    /// EXDEV. The write is redone beside the key and lands; nothing stays in staging.
    /// Skipped where no second filesystem is available.
    #[tokio::test]
    async fn write_across_a_mount_point_falls_back_beside_the_key() {
        use std::os::unix::fs::MetadataExt;
        let Ok(other_fs) = TempDir::new_in("/dev/shm") else {
            eprintln!("skip: /dev/shm unavailable, cannot force EXDEV");
            return;
        };
        let dir = TempDir::new().unwrap();
        if std::fs::metadata(other_fs.path()).unwrap().dev()
            == std::fs::metadata(dir.path()).unwrap().dev()
        {
            eprintln!("skip: /dev/shm and the temp dir share a filesystem, no EXDEV");
            return;
        }
        std::os::unix::fs::symlink(other_fs.path(), dir.path().join("npm")).unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let data = vec![7u8; 100_000];

        put(&storage, "npm/pkg/-/pkg-1.0.0.tgz", &data)
            .await
            .unwrap();

        assert_eq!(
            get(&storage, "npm/pkg/-/pkg-1.0.0.tgz").await.unwrap(),
            data
        );
        let leftovers = tmp_leftovers(dir.path());
        let elsewhere = tmp_leftovers(other_fs.path());
        assert!(
            leftovers.is_empty() && elsewhere.is_empty(),
            "{leftovers:?} {elsewhere:?}"
        );
    }

    /// `put_from_path` into a key on another filesystem than both the spool and the
    /// staging directory: the direct rename and the rename out of staging both fail
    /// with EXDEV, and the copy beside the key lands. Skipped where no second
    /// filesystem is available.
    #[tokio::test]
    async fn put_from_path_across_a_mount_point_lands() {
        use std::os::unix::fs::MetadataExt;
        let Ok(other_fs) = TempDir::new_in("/dev/shm") else {
            eprintln!("skip: /dev/shm unavailable, cannot force EXDEV");
            return;
        };
        let dir = TempDir::new().unwrap();
        if std::fs::metadata(other_fs.path()).unwrap().dev()
            == std::fs::metadata(dir.path()).unwrap().dev()
        {
            eprintln!("skip: /dev/shm and the temp dir share a filesystem, no EXDEV");
            return;
        }
        std::os::unix::fs::symlink(other_fs.path(), dir.path().join("docker")).unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        let spool = dir.path().join("tmp/docker-proxy/spool-1");
        std::fs::create_dir_all(spool.parent().unwrap()).unwrap();
        let data = vec![3u8; 100_000];
        std::fs::write(&spool, &data).unwrap();

        storage
            .put_from_path("docker/blobs/sha256-ab", &spool, None)
            .await
            .unwrap();

        assert_eq!(get(&storage, "docker/blobs/sha256-ab").await.unwrap(), data);
        assert!(!spool.exists(), "the spool is consumed");
        let leftovers = tmp_leftovers(dir.path());
        let elsewhere = tmp_leftovers(other_fs.path());
        assert!(
            leftovers.is_empty() && elsewhere.is_empty(),
            "{leftovers:?} {elsewhere:?}"
        );
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        put(&storage, "test/key", b"test data").await.unwrap();
        let data = get(&storage, "test/key").await.unwrap();
        assert_eq!(&*data, b"test data");
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        let result = get(&storage, "nonexistent").await;
        assert!(matches!(result, Err(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn test_list_with_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        put(&storage, "docker/image/blob1", b"data1").await.unwrap();
        put(&storage, "docker/image/blob2", b"data2").await.unwrap();
        put(&storage, "maven/artifact", b"data3").await.unwrap();

        let docker_keys = storage.list("docker/").await.unwrap();
        assert_eq!(docker_keys.len(), 2);
        assert!(docker_keys.iter().all(|k| k.starts_with("docker/")));

        let all_keys = storage.list("").await.unwrap();
        assert_eq!(all_keys.len(), 3);
    }

    #[tokio::test]
    async fn list_excludes_signing_key() {
        // The repository signing key lives at `<storage.path>/.signing/nora.key`
        // (main.rs default) and is persisted owner-only (0600, signing.rs:182). It is
        // a SECRET, not an artifact: list() must never enumerate it, or backup/migrate/
        // GC/UI would leak it (0644 tarball / plaintext S3 object) or GC could delete
        // the signing identity. Regression guard for the #891-class export leak.
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        put(&storage, "npm/left-pad/-/left-pad-1.0.0.tgz", b"artifact")
            .await
            .unwrap();
        std::fs::create_dir_all(temp_dir.path().join(".signing")).unwrap();
        std::fs::write(temp_dir.path().join(".signing/nora.key"), b"SECRET-KEY").unwrap();

        let all = storage.list("").await.unwrap();
        assert!(
            all.iter().any(|k| k.contains("left-pad")),
            "real artifact must still be listed: {all:?}"
        );
        assert!(
            !all.iter().any(|k| k.starts_with(".signing/")),
            "signing key must never be enumerated by list(\"\"): {all:?}"
        );

        // Even an explicit prefix must not surface it.
        let signing = storage.list(".signing/").await.unwrap();
        assert!(
            signing.is_empty(),
            "explicit .signing/ prefix must still exclude the key: {signing:?}"
        );

        // list_with_meta shares the walk — it must exclude it too.
        let meta = storage.list_with_meta("").await.unwrap();
        assert!(
            !meta.iter().any(|(k, _)| k.starts_with(".signing/")),
            "list_with_meta must exclude the signing key: {:?}",
            meta.iter().map(|(k, _)| k).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_stat() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        put(&storage, "test", b"12345").await.unwrap();
        let meta = storage.stat("test").await.unwrap();
        assert_eq!(meta.size, 5);
        assert!(meta.modified > 0);
    }

    #[tokio::test]
    async fn test_stat_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        let meta = storage.stat("nonexistent").await;
        assert!(meta.is_none());
    }

    #[tokio::test]
    async fn test_health_check() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());
        assert!(storage.health_check().await);
    }

    #[tokio::test]
    async fn test_health_check_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let new_path = temp_dir.path().join("new_storage");
        let storage = LocalStorage::new(new_path.to_str().unwrap());

        assert!(!new_path.exists());
        assert!(storage.health_check().await);
        assert!(new_path.exists());
    }

    #[tokio::test]
    async fn test_health_check_fails_when_unwritable() {
        // base_path *under a regular file* can't be created or written: `open`
        // fails with ENOTDIR — a structural error the kernel returns even to
        // root, unlike a chmod'd read-only dir which root bypasses via
        // DAC_OVERRIDE. The old `exists()`-only check would have missed this.
        let temp_dir = TempDir::new().unwrap();
        let file = temp_dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let storage = LocalStorage::new(file.join("store").to_str().unwrap());
        assert!(
            !storage.health_check().await,
            "an unwritable backing store must report unhealthy"
        );
    }

    #[tokio::test]
    async fn test_nested_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        put(&storage, "a/b/c/d/e/file", b"deep").await.unwrap();
        let data = get(&storage, "a/b/c/d/e/file").await.unwrap();
        assert_eq!(&*data, b"deep");
    }

    #[tokio::test]
    async fn test_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        put(&storage, "key", b"original").await.unwrap();
        put(&storage, "key", b"updated").await.unwrap();

        let data = get(&storage, "key").await.unwrap();
        assert_eq!(&*data, b"updated");
    }

    #[test]
    fn test_backend_name() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());
        assert_eq!(storage.backend_name(), "local");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_writes_same_key() {
        let temp_dir = TempDir::new().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_str().unwrap()));

        let mut handles = Vec::new();
        for i in 0..10u8 {
            let s = storage.clone();
            handles.push(tokio::spawn(async move {
                let data = vec![i; 1024];
                put(&s, "shared/key", &data).await
            }));
        }

        for h in handles {
            h.await.expect("task panicked").expect("put failed");
        }

        let data = get(&storage, "shared/key").await.expect("get failed");
        assert_eq!(data.len(), 1024);
        let first = data[0];
        assert!(
            data.iter().all(|&b| b == first),
            "file is corrupted — mixed writers"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_writes_different_keys() {
        let temp_dir = TempDir::new().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_str().unwrap()));

        let mut handles = Vec::new();
        for i in 0..10u32 {
            let s = storage.clone();
            handles.push(tokio::spawn(async move {
                let key = format!("key/{}", i);
                put(&s, &key, format!("data-{}", i).as_bytes()).await
            }));
        }

        for h in handles {
            h.await.expect("task panicked").expect("put failed");
        }

        for i in 0..10u32 {
            let key = format!("key/{}", i);
            let data = get(&storage, &key).await.expect("get failed");
            assert_eq!(&*data, format!("data-{}", i).as_bytes());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_read_during_write() {
        // The put path writes a temp file, fsyncs it, and atomically renames it
        // into place, so a concurrent reader observes either the complete old
        // object or the complete new one — never a torn mix of both, never a
        // partial length, and never a missing key (the destination always
        // resolves to one inode or the other). This asserts that invariant under
        // contention: a non-atomic write (write-in-place, or unlink-then-write)
        // would expose a torn read or a NotFound here and fail.
        use std::sync::atomic::{AtomicBool, Ordering};

        const LEN: usize = 1 << 16; // 64 KiB — wide enough that a non-atomic write tears

        let temp_dir = TempDir::new().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_str().unwrap()));
        put(&storage, "rw/key", &vec![0u8; LEN])
            .await
            .expect("seed put");

        let done = std::sync::Arc::new(AtomicBool::new(false));

        let sw = storage.clone();
        let dw = done.clone();
        let writer = tokio::spawn(async move {
            // Alternate all-0x00 and all-0x01 payloads so any torn read is a
            // visible mix of the two.
            for i in 0..100u32 {
                let byte = if i % 2 == 0 { 0u8 } else { 1u8 };
                put(&sw, "rw/key", &vec![byte; LEN])
                    .await
                    .expect("put failed");
            }
            dw.store(true, Ordering::Release);
        });

        let sr = storage.clone();
        let dr = done.clone();
        let reader = tokio::spawn(async move {
            // Spin for the whole write loop so the concurrent window is exercised.
            while !dr.load(Ordering::Acquire) {
                match get(&sr, "rw/key").await {
                    Ok(data) => {
                        assert_eq!(data.len(), LEN, "torn/partial read: wrong object length");
                        let first = data[0];
                        assert!(
                            data.iter().all(|&b| b == first),
                            "torn read: object mixes old (0x00) and new (0x01) bytes — atomic rename violated"
                        );
                    }
                    Err(crate::storage::StorageError::NotFound) => {
                        panic!(
                            "key vanished mid-write — atomic rename violated (unlink-then-write?)"
                        )
                    }
                    Err(e) => panic!("unexpected error: {}", e),
                }
            }
        });

        writer.await.expect("writer panicked");
        reader.await.expect("reader panicked");

        // Final state is a complete, uniform object.
        let data = get(&storage, "rw/key").await.expect("final get");
        assert_eq!(data.len(), LEN);
        let first = data[0];
        assert!(
            data.iter().all(|&b| b == first),
            "final state must be a uniform object"
        );
    }

    #[tokio::test]
    async fn test_total_size_empty() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());
        assert_eq!(storage.total_size().await, 0);
    }

    #[tokio::test]
    async fn test_total_size_with_files() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        put(&storage, "a/file1", b"hello").await.unwrap(); // 5 bytes
        put(&storage, "b/file2", b"world!").await.unwrap(); // 6 bytes

        let size = storage.total_size().await;
        assert_eq!(size, 11);
    }

    #[tokio::test]
    async fn test_total_size_after_delete() {
        let temp_dir = TempDir::new().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_str().unwrap());

        put(&storage, "file1", b"12345").await.unwrap();
        put(&storage, "file2", b"67890").await.unwrap();
        assert_eq!(storage.total_size().await, 10);

        storage.delete("file1").await.unwrap();
        assert_eq!(storage.total_size().await, 5);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_deletes_same_key() {
        let temp_dir = TempDir::new().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_str().unwrap()));

        put(&storage, "del/key", b"ephemeral").await.expect("put");

        let mut handles = Vec::new();
        for _ in 0..10 {
            let s = storage.clone();
            handles.push(tokio::spawn(async move {
                let _ = s.delete("del/key").await;
            }));
        }

        for h in handles {
            h.await.expect("task panicked");
        }

        assert!(matches!(
            get(&storage, "del/key").await,
            Err(crate::storage::StorageError::NotFound)
        ));
    }

    async fn put_key(storage: &LocalStorage, key: &str) {
        use sha2::Digest as _;
        let sha = hex::encode(sha2::Sha256::digest(b"x"));
        storage.put(key, b"x", &sha).await.unwrap();
    }

    /// Keys of `list` and `list_with_meta` for `prefix`, or `None` if either has not
    /// returned within `secs` (the walk runs on its own thread so a runaway walk
    /// fails the probe instead of hanging the test binary).
    fn list_both_within(
        root: &Path,
        prefix: &str,
        secs: u64,
    ) -> Option<(Vec<String>, Vec<String>)> {
        let (tx, rx) = std::sync::mpsc::channel();
        let (root, prefix) = (root.to_str().unwrap().to_string(), prefix.to_string());
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let storage = LocalStorage::new(&root);
            let listed = rt.block_on(storage.list(&prefix)).unwrap();
            let meta = rt
                .block_on(storage.list_with_meta(&prefix))
                .unwrap()
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            let _ = tx.send((listed, meta));
            rt.shutdown_background();
        });
        rx.recv_timeout(std::time::Duration::from_secs(secs)).ok()
    }

    /// Two self-loops at `dir`: a walk that enters `dir` never finishes
    /// (2 branches per level, until ELOOP at ~40 levels).
    fn plant_loops(dir: &Path) {
        std::os::unix::fs::symlink(".", dir.join("loop_a")).unwrap();
        std::os::unix::fs::symlink(".", dir.join("loop_b")).unwrap();
    }

    /// The walk for a prefix starts in the directory its last `/` names and in no directory
    /// above it: loops planted at the root and at every level between the root and that
    /// directory make a walk from any of them never return. Same keys are not enough — the
    /// point of starting at the prefix is not reading the rest of the store.
    #[tokio::test]
    async fn a_prefix_listing_walks_no_directory_above_the_one_it_names() {
        let keys = [
            "npm/pkg/versions/1.0.0.json",
            "npm/pkg/versions/1.1.0.json",
            "npm/pkg/versions-old/0.9.0.json",
            "npm/pkg/pkg-1.0.0.tgz",
            "npm/pkgx/versions/2.0.0.json",
            "raw/a",
        ];
        for prefix in [
            "npm/pkg/versions/",
            "npm/pkg/versions/1.",
            "npm/pkg/",
            "npm/pkg",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let storage = LocalStorage::new(dir.path().to_str().unwrap());
            for key in keys {
                put_key(&storage, key).await;
            }
            let mut want: Vec<String> = keys
                .iter()
                .filter(|k| k.starts_with(prefix))
                .map(|k| k.to_string())
                .collect();
            want.sort();
            // The root, then `npm`, `npm/pkg`, ... down to (not including) the named directory.
            let named = &prefix[..prefix.rfind('/').unwrap()];
            plant_loops(dir.path());
            for (i, _) in named.match_indices('/') {
                plant_loops(&dir.path().join(&named[..i]));
            }
            let got = list_both_within(dir.path(), prefix, 20)
                .unwrap_or_else(|| panic!("listing {prefix:?} walked above {named:?}"));
            assert_eq!(got, (want.clone(), want), "{prefix:?}");
        }
    }

    /// An absolute prefix has an empty first component: the walk starts at the storage root,
    /// never at the absolute directory the prefix names outside the store.
    #[tokio::test]
    async fn an_absolute_prefix_never_walks_outside_the_store() {
        let top = tempfile::tempdir().unwrap();
        let store = top.path().join("store");
        let outside = top.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let storage = LocalStorage::new(store.to_str().unwrap());
        put_key(&storage, "raw/a").await;
        plant_loops(&outside);
        assert_eq!(list_root(&store, "/etc/"), Some(store.clone()));
        let prefix = format!("{}/", outside.to_str().unwrap());
        let got = list_both_within(&store, &prefix, 20)
            .expect("an absolute prefix walked a directory outside the store");
        assert_eq!(got, (vec![], vec![]));
    }

    /// `npm/./pkg/` names no key (no key has a `.` component); a walk started at `npm/.`
    /// would report keys spelled `npm/./pkg/...`.
    #[tokio::test]
    async fn a_prefix_with_a_dot_component_lists_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        put_key(&storage, "npm/pkg/versions/1.0.0.json").await;
        for prefix in ["npm/./pkg/", "npm/./", "./npm/pkg/"] {
            assert_eq!(
                storage.list(prefix).await.unwrap(),
                Vec::<String>::new(),
                "{prefix:?}"
            );
            assert!(
                storage.list_with_meta(prefix).await.unwrap().is_empty(),
                "{prefix:?}"
            );
        }
    }

    /// #1154: a write without a digest whose tombstone cannot reach the disk reports it, as a
    /// pin that cannot is reported: the stale pin left behind would fail every read of the new
    /// bytes.
    #[tokio::test]
    async fn a_write_whose_tombstone_cannot_be_written_fails() {
        use sha2::Digest;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let storage = LocalStorage::new(store.to_str().unwrap());
        let file = |name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        };
        let sha = |b: &[u8]| hex::encode(sha2::Sha256::digest(b));
        for key in ["raw/k", "raw/t"] {
            storage
                .put_from_path(key, &file("v1", b"v1"), Some(&sha(b"v1")))
                .await
                .unwrap();
        }
        storage
            .put_from_path("raw/u", &file("u", b"u"), None)
            .await
            .unwrap();
        // The pin file can no longer be appended to.
        let pins = store.join(PIN_FILE);
        std::fs::remove_file(&pins).unwrap();
        std::fs::create_dir(&pins).unwrap();
        assert!(storage
            .put_from_path("raw/k", &file("v2", b"v2"), None)
            .await
            .is_err());
        assert!(storage.copy("raw/u", "raw/t", None).await.is_err());
    }

    /// Only the staging directory itself, at the root and spelled exactly, is left out; a key
    /// whose path merely contains or starts with that name is listed as the full walk lists it.
    #[tokio::test]
    async fn only_the_staging_directory_at_the_root_is_left_out_of_a_listing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = LocalStorage::new(dir.path().to_str().unwrap());
        // Valid keys (validate_storage_key checks only the first segment).
        for key in ["raw/g/.nora-staging/f", ".nora-stagingx/a/f"] {
            crate::validation::validate_storage_key(key).unwrap();
            put_key(&storage, key).await;
        }
        let mut rows = vec![
            ("raw/g/.nora-staging/", "raw/g/.nora-staging/f"),
            (".nora-stagingx/a/", ".nora-stagingx/a/f"),
        ];
        // Not writable through the API, but on disk the full walk lists it. On a file system
        // that ignores case (APFS, NTFS) `.NORA-STAGING` is the staging directory itself, so
        // the spelling the row tells apart exists only where the file system keeps it (#1156).
        std::fs::write(dir.path().join("case-probe"), b"").unwrap();
        if !dir.path().join("CASE-PROBE").exists() {
            std::fs::create_dir_all(dir.path().join(".NORA-STAGING/x")).unwrap();
            std::fs::write(dir.path().join(".NORA-STAGING/x/f"), b"x").unwrap();
            rows.push((".NORA-STAGING/x/", ".NORA-STAGING/x/f"));
        }
        for (prefix, key) in rows {
            let mut full = Vec::new();
            LocalStorage::list_files_sync(
                &dir.path().to_path_buf(),
                &dir.path().to_path_buf(),
                prefix,
                &mut full,
            );
            assert_eq!(full, vec![key.to_string()], "oracle {prefix:?}");
            assert_eq!(storage.list(prefix).await.unwrap(), full, "list {prefix:?}");
            let meta: Vec<String> = storage
                .list_with_meta(prefix)
                .await
                .unwrap()
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            assert_eq!(meta, full, "list_with_meta {prefix:?}");
        }
    }
}
