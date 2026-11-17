// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! How long a request waits for the object store to answer (#1182).
//!
//! The object store client retries a request for as long as a slow download may take (see
//! `STREAM_ATTEMPT_TIMEOUT`), so a store that is down or does not answer kept a download
//! waiting for minutes. Here the wait for the store's ANSWER is bounded: a read is given
//! `[storage] answer_timeout_secs` to bring the response headers (a listing: each page), and
//! a body that has started is left to stream at its own pace. A store that has not answered,
//! or answered with a transport failure, is noted on the request ([`scope`]) so the response
//! can say "storage unavailable" (503) instead of the 404 or 500 a handler made of it, and
//! writes are refused at once until the store answers again, so they do not pile up behind it.
//!
//! The note is a task-local of the request: storage code outside a request (background tasks,
//! schedulers, the CLI) writes it nowhere and is not affected by it.

use async_trait::async_trait;
use futures::stream::{BoxStream, StreamExt};
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
    PutMultipartOptions, PutOptions, PutPayload, PutResult,
};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

tokio::task_local! {
    /// Set when the object store did not answer a call of the current request.
    static UNANSWERED: Cell<bool>;
}

/// Runs `request` with its own note of whether the object store left it unanswered, and
/// returns the note with the request's output.
pub async fn scope<F: std::future::Future>(request: F) -> (F::Output, bool) {
    UNANSWERED
        .scope(Cell::new(false), async {
            let output = request.await;
            let unanswered = UNANSWERED.with(Cell::get);
            (output, unanswered)
        })
        .await
}

/// Whether the caller runs inside a request ([`scope`]).
fn in_request() -> bool {
    UNANSWERED.try_with(|_| ()).is_ok()
}

/// Notes on the current request, if there is one, that the store did not answer it.
pub(crate) fn note_unanswered() {
    let _ = UNANSWERED.try_with(|note| note.set(true));
}

/// Whether the object store left the current request unanswered so far; `false` outside a
/// request.
pub fn unanswered_in_this_request() -> bool {
    UNANSWERED.try_with(Cell::get).unwrap_or(false)
}

/// Why a call was not passed to the store or not waited for.
#[derive(Debug, thiserror::Error)]
pub enum Unanswered {
    /// The store did not answer within the answer timeout.
    #[error("the object store did not answer within {0:?}")]
    Timeout(Duration),
    /// A write while the store has not answered since a read it left unanswered.
    #[error("the object store has not answered since its last unanswered request")]
    NoAnswerSince,
    /// A read of a request the store already left unanswered: not waited for a second time.
    #[error("the object store did not answer this request")]
    EarlierInThisRequest,
}

impl From<Unanswered> for object_store::Error {
    fn from(why: Unanswered) -> Self {
        object_store::Error::Generic {
            store: STORE,
            source: Box::new(why),
        }
    }
}

/// The `store` name of the errors made here, to tell them from the store's own.
const STORE: &str = "answer";

/// Why the store was not waited for or not asked, when `error` was made here; otherwise
/// `error` back, as the store gave it.
pub fn unanswered_of(error: object_store::Error) -> Result<Unanswered, object_store::Error> {
    match error {
        object_store::Error::Generic { store, source } if store == STORE => source
            .downcast::<Unanswered>()
            .map(|why| *why)
            .map_err(|source| object_store::Error::Generic { store, source }),
        other => Err(other),
    }
}

/// The answer timeout and what the store's answers have shown, shared by the store wrapper
/// and its owner.
#[derive(Debug, Default)]
pub struct AnswerPolicy {
    /// Milliseconds; `0` = no limit, as before #1182, and nothing noted or refused.
    limit_ms: AtomicU64,
    /// A read went unanswered (timeout or transport failure) and nothing has answered since.
    lost: AtomicBool,
}

impl AnswerPolicy {
    /// Sets the answer timeout; `None` lifts it, and with it every effect of this module.
    pub fn set_limit(&self, limit: Option<Duration>) {
        let ms = limit.map_or(0, |d| {
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
        });
        self.limit_ms.store(ms, Ordering::Relaxed);
        if ms == 0 {
            self.lost.store(false, Ordering::Relaxed);
        }
    }

    fn limit(&self) -> Option<Duration> {
        match self.limit_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    /// The store answered: writes go to it again.
    pub fn answered(&self) {
        self.lost.store(false, Ordering::Relaxed);
    }

    fn unanswered(&self) {
        self.lost.store(true, Ordering::Relaxed);
        note_unanswered();
    }

    /// Takes in what a call brought. An answer the store gave, including "not found", "already
    /// exists" and "precondition failed", is an answer; a transport failure (connection, TLS,
    /// a 5xx after the client's retries: object_store's `Generic`) is not.
    fn observe<T>(&self, result: &object_store::Result<T>) {
        match result {
            Ok(_)
            | Err(object_store::Error::NotFound { .. })
            | Err(object_store::Error::AlreadyExists { .. })
            | Err(object_store::Error::Precondition { .. })
            | Err(object_store::Error::NotModified { .. }) => self.answered(),
            Err(object_store::Error::Generic { .. }) => self.unanswered(),
            Err(_) => {}
        }
    }

    /// Waits for `call` at most the answer timeout, and takes in what it brought. Outside a
    /// request (background tasks, schedulers, the CLI) the call is waited for as long as the
    /// client retries and changes nothing here, as before #1182.
    async fn read<T>(
        &self,
        call: impl std::future::Future<Output = object_store::Result<T>>,
    ) -> object_store::Result<T> {
        let Some(limit) = self.limit().filter(|_| in_request()) else {
            return call.await;
        };
        // One wait per request: once the store has left it unanswered, the request's further
        // reads end at once, and the request is answered within about one timeout.
        if unanswered_in_this_request() {
            return Err(Unanswered::EarlierInThisRequest.into());
        }
        // CANCEL-SAFETY: only reads (and a listing page) are waited for here; a call dropped
        // before the store answered has changed nothing in it.
        let result = match tokio::time::timeout(limit, call).await {
            Ok(result) => result,
            Err(_) => Err(Unanswered::Timeout(limit).into()),
        };
        self.observe(&result);
        result
    }

    /// Refuses a write at once while the store has not answered since it left a read
    /// unanswered; otherwise lets it through and takes in what it brought.
    async fn write<T>(
        &self,
        call: impl std::future::Future<Output = object_store::Result<T>>,
    ) -> object_store::Result<T> {
        if self.limit().is_none() {
            return call.await;
        }
        if self.lost.load(Ordering::Relaxed) {
            note_unanswered();
            return Err(Unanswered::NoAnswerSince.into());
        }
        let result = call.await;
        if in_request() {
            self.observe(&result);
        }
        result
    }
}

/// An object store whose answers are waited for as [`AnswerPolicy`] says.
#[derive(Debug)]
pub struct Answering {
    inner: Box<dyn ObjectStore>,
    policy: Arc<AnswerPolicy>,
}

impl Answering {
    /// `inner`, with no answer timeout until the policy sets one.
    pub fn new(inner: Box<dyn ObjectStore>) -> Self {
        Self {
            inner,
            policy: Arc::default(),
        }
    }

    /// The policy, to set the timeout and to report answers seen elsewhere.
    pub fn policy(&self) -> &AnswerPolicy {
        &self.policy
    }

    /// The store itself, for the maintenance probes, which keep their own deadlines: `/ready`
    /// is decided as before #1182.
    pub fn unbounded(&self) -> &dyn ObjectStore {
        self.inner.as_ref()
    }
}

impl std::fmt::Display for Answering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[async_trait]
impl ObjectStore for Answering {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        self.policy
            .write(self.inner.put_opts(location, payload, opts))
            .await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.policy
            .write(self.inner.put_multipart_opts(location, opts))
            .await
    }

    async fn get_opts(
        &self,
        location: &Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        // The result comes with the response headers; its body streams after, unbounded here.
        self.policy
            .read(self.inner.get_opts(location, options))
            .await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<Path>>,
    ) -> BoxStream<'static, object_store::Result<Path>> {
        if self.policy.limit().is_some() && self.policy.lost.load(Ordering::Relaxed) {
            note_unanswered();
            return locations
                .map(|_| Err(Unanswered::NoAnswerSince.into()))
                .boxed();
        }
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        let pages = self.inner.list(prefix);
        if self.policy.limit().is_none() || !in_request() {
            return pages;
        }
        // Each item is waited for at most the answer timeout: the items of a page come at
        // once, so this bounds each page's request. The first unanswered one ends the listing.
        let policy = Arc::clone(&self.policy);
        futures::stream::unfold(Some(pages), move |pages| {
            let policy = Arc::clone(&policy);
            async move {
                let mut pages = pages?;
                let next = policy
                    .read(async { pages.next().await.transpose() })
                    .await
                    .transpose()?;
                let more = next.is_ok().then_some(pages);
                Some((next, more))
            }
        })
        .boxed()
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.policy
            .read(self.inner.list_with_delimiter(prefix))
            .await
    }

    async fn copy_opts(
        &self,
        from: &Path,
        to: &Path,
        options: CopyOptions,
    ) -> object_store::Result<()> {
        self.policy
            .write(self.inner.copy_opts(from, to, options))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{ObjectStorage, StorageBackend, StorageError};

    const ANSWER: Duration = Duration::from_millis(300);

    /// A store that takes every call and never answers.
    #[derive(Debug)]
    struct Stalled;

    impl std::fmt::Display for Stalled {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Stalled")
        }
    }

    #[async_trait]
    impl ObjectStore for Stalled {
        async fn put_opts(
            &self,
            _: &Path,
            _: PutPayload,
            _: PutOptions,
        ) -> object_store::Result<PutResult> {
            std::future::pending().await
        }
        async fn put_multipart_opts(
            &self,
            _: &Path,
            _: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn MultipartUpload>> {
            std::future::pending().await
        }
        async fn get_opts(&self, _: &Path, _: GetOptions) -> object_store::Result<GetResult> {
            std::future::pending().await
        }
        fn delete_stream(
            &self,
            _: BoxStream<'static, object_store::Result<Path>>,
        ) -> BoxStream<'static, object_store::Result<Path>> {
            futures::stream::pending().boxed()
        }
        fn list(&self, _: Option<&Path>) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
            futures::stream::pending().boxed()
        }
        async fn list_with_delimiter(&self, _: Option<&Path>) -> object_store::Result<ListResult> {
            std::future::pending().await
        }
        async fn copy_opts(&self, _: &Path, _: &Path, _: CopyOptions) -> object_store::Result<()> {
            std::future::pending().await
        }
    }

    fn stalled() -> ObjectStorage {
        let storage = ObjectStorage::over(Box::new(Stalled));
        storage.set_answer_timeout(Some(ANSWER));
        storage
    }

    /// Every read of a request is waited for at most the answer timeout, the request is
    /// noted, and the read says why.
    #[tokio::test(start_paused = true)]
    async fn a_read_the_store_does_not_answer_ends_at_the_timeout_and_is_noted() {
        let storage = stalled();
        let reads = scope(async {
            (
                storage.get("raw/a.txt").await.err(),
                storage.get_reader("raw/a.txt").await.err(),
                storage.get_range("raw/a.txt", 0, 1).await.err(),
                storage.stat("raw/a.txt").await,
                storage.list("raw/").await.err(),
            )
        });
        // CANCEL-SAFETY: reads only. The deadline turns a read that is never cut into a failure.
        let (results, unanswered) = tokio::time::timeout(ANSWER * 20, reads)
            .await
            .expect("a read waited past the answer timeout");
        assert!(unanswered);
        let (get, reader, range, stat, list) = results;
        assert!(
            matches!(get, Some(StorageError::Unavailable(Unanswered::Timeout(_)))),
            "{get:?}"
        );
        for err in [reader, range, list] {
            assert!(
                matches!(
                    err,
                    Some(StorageError::Unavailable(Unanswered::EarlierInThisRequest))
                ),
                "{err:?}"
            );
        }
        assert!(stat.is_none());
    }

    /// A request waits for the store once: after a read the store left unanswered (a scoped
    /// key's fallback to its pre-#534 spelling included), the request's further reads end at
    /// once, so the request is answered within about one timeout.
    #[tokio::test(start_paused = true)]
    async fn a_request_the_store_does_not_answer_is_waited_for_once() {
        let storage = stalled();
        let started = tokio::time::Instant::now();
        let reads = scope(async {
            let _ = storage.stat("npm/@scope/pkg/metadata.json").await;
            let after_stat = started.elapsed();
            let _ = storage.pin("npm/@scope/pkg/-/pkg-1.0.0.tgz").await;
            (after_stat, started.elapsed() - after_stat)
        });
        // CANCEL-SAFETY: reads only. The deadline turns a read that is never cut into a failure.
        let ((stat, pin), _) = tokio::time::timeout(ANSWER * 20, reads)
            .await
            .expect("a read waited past the answer timeout");
        assert_eq!(stat, ANSWER);
        assert_eq!(pin, Duration::ZERO);
    }

    /// "Not found", "already exists" and "precondition failed" are the store's answers:
    /// they note nothing, and writes go on.
    #[tokio::test]
    async fn the_stores_own_answers_note_nothing() {
        let storage = ObjectStorage::in_memory();
        storage.set_answer_timeout(Some(ANSWER));
        let (absent, unanswered) = scope(async {
            let absent = storage.get("raw/absent.txt").await;
            storage.put("raw/new.txt", b"x", "").await.unwrap();
            absent
        })
        .await;
        assert!(matches!(absent, Err(StorageError::NotFound)), "{absent:?}");
        assert!(!unanswered);
    }

    /// After a read the store left unanswered, writes are refused at once, in the request
    /// and outside it (a cache write spawned from it), until the store answers again.
    #[tokio::test(start_paused = true)]
    async fn writes_are_refused_until_the_store_answers_again() {
        let storage = stalled();
        let calls = scope(async {
            let _ = storage.get("raw/a.txt").await;
            storage.put("raw/b.txt", b"x", "").await
        });
        // CANCEL-SAFETY: a refused write changes nothing. The deadline turns a write let through
        // to a store that never answers into a failure.
        let (refused, _) = tokio::time::timeout(ANSWER * 20, calls)
            .await
            .expect("a write waited for the store");
        assert!(
            matches!(
                refused,
                Err(StorageError::Unavailable(Unanswered::NoAnswerSince))
            ),
            "{refused:?}"
        );
        // CANCEL-SAFETY: as above.
        let outside = tokio::time::timeout(ANSWER, storage.put("raw/c.txt", b"x", ""))
            .await
            .expect("a write waited for the store");
        assert!(
            matches!(
                outside,
                Err(StorageError::Unavailable(Unanswered::NoAnswerSince))
            ),
            "{outside:?}"
        );

        storage.answer_policy().answered();
        // CANCEL-SAFETY: a write to a store that never answers; nothing lands.
        let let_through = tokio::time::timeout(
            Duration::from_secs(3600),
            storage.put("raw/d.txt", b"x", ""),
        )
        .await;
        assert!(
            let_through.is_err(),
            "the write was not let through to the store"
        );
    }

    /// No timeout: nothing is bounded, noted or refused, as before #1182.
    #[tokio::test(start_paused = true)]
    async fn without_a_timeout_nothing_changes() {
        let storage = ObjectStorage::over(Box::new(Stalled));
        storage.set_answer_timeout(None);
        let (waited, unanswered) = scope(async {
            // CANCEL-SAFETY: a read of a key; dropped at the deadline, it leaves nothing behind.
            tokio::time::timeout(Duration::from_secs(3600), storage.get("raw/a.txt")).await
        })
        .await;
        assert!(waited.is_err());
        assert!(!unanswered);
    }
}
