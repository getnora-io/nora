// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Compile-time integrity witnesses for stored artifacts (typestate).
//!
//! NORA already enforces its integrity guarantees at runtime: the buffered
//! [`Storage::get`](crate::storage::Storage::get) gate hash-pin-verifies bytes
//! before returning them (`#582`/`#604`), the streaming docker path
//! tamper-detects at EOF, and `put` couples the body write with a hash-pin
//! record on the local backend. This module pushes those guarantees one step
//! **left** — into the type system — and, just as importantly, makes the
//! *known holes* impossible to hide.
//!
//! # The honest tiers (grounded in live code)
//!
//! A served-bytes value carries a zero-sized [`Integrity`] witness `S`:
//!
//! - [`Verified`] — the bytes were SHA-256-checked against an expected digest
//!   and **matched**. This is *sound by construction*: the only constructor,
//!   [`Blob::<Verified>::verify`], performs the hash itself, so possessing a
//!   `Blob<Verified>` is a proof that `sha256(bytes) == expected`. No `unsafe`,
//!   no privileged constructor, no cross-crate seal to trust. What `expected`
//!   *means* is the caller's to state: for a hash-pinned cache read it is the
//!   digest NORA recorded at store time (tamper-evidence against on-disk
//!   corruption — `src/storage/mod.rs:260`), and for a content-addressed
//!   artifact (a docker blob, whose key *is* its digest) it is the canonical
//!   upstream digest.
//!
//! - [`TamperEvident`] — streamed bytes whose digest is verified only at EOF
//!   (`src/registry/docker.rs`, `VerifyingReader`). A mismatch aborts the
//!   response, but bytes already streamed cannot be un-sent. Strictly weaker
//!   than [`Verified`]; named so it can never be silently treated as the strong
//!   tier.
//!
//! - [`Unverified`] — raw bytes with no NORA-side integrity guarantee: a
//!   streaming `get_reader`/`get_range` read, an in-memory buffer, or
//!   proxy-upstream bytes that were never NORA-stored.
//!
//! # Why this is push-left, not theatre
//!
//! A serve sink that demands `Blob<Verified>` (see [`verified_body`]) *cannot*
//! be handed raw or merely-tamper-evident bytes — that is a compile error, not
//! a runtime check that a future refactor might skip. And the open-world hole
//! (an unpinned key, or the S3 backend which has no pin store at all) is forced
//! into the open by [`GateOutcome`]: a caller of
//! [`Storage::get_verified`](crate::storage::Storage::get_verified) must
//! `match` and decide what to do with [`GateOutcome::Unpinned`] — it can never
//! be mistaken for a cryptographically verified read.
//!
//! Compile-fail proofs live in `tests/typestate_compile_fail.rs` (trybuild);
//! the positive direction is unit-tested below.

use std::marker::PhantomData;

/// Sealed so no code outside this module can add an integrity tier or impl the
/// [`Integrity`] trait for a forged marker.
mod sealed {
    pub trait Sealed {}
}

/// The integrity tier of a [`Blob`]. Sealed: the variants are exactly
/// [`Unverified`], [`TamperEvident`], and [`Verified`].
pub trait Integrity: sealed::Sealed {
    /// Short tier name, for logs and metrics.
    const TIER: &'static str;
    /// `true` only for the strong (digest-matched) tier.
    const IS_VERIFIED: bool;
}

/// Raw bytes with no NORA-side integrity guarantee (streaming read, in-memory
/// buffer, or never-NORA-stored upstream bytes). Uninhabited — used only as a
/// type tag.
#[derive(Debug)]
pub enum Unverified {}

/// Streamed bytes verified at EOF only: a mismatch aborts the response but
/// cannot un-send bytes already sent. Weaker than [`Verified`]. Uninhabited.
#[derive(Debug)]
pub enum TamperEvident {}

/// Bytes whose SHA-256 matched an expected digest. The strong tier; mintable
/// only by [`Blob::<Verified>::verify`], which performs the check. Uninhabited.
#[derive(Debug)]
pub enum Verified {}

impl sealed::Sealed for Unverified {}
impl sealed::Sealed for TamperEvident {}
impl sealed::Sealed for Verified {}

impl Integrity for Unverified {
    const TIER: &'static str = "unverified";
    const IS_VERIFIED: bool = false;
}
impl Integrity for TamperEvident {
    const TIER: &'static str = "tamper-evident";
    const IS_VERIFIED: bool = false;
}
impl Integrity for Verified {
    const TIER: &'static str = "verified";
    const IS_VERIFIED: bool = true;
}

/// A payload `T` tagged with its compile-time [`Integrity`] tier `S`.
///
/// The payload is private: the only way to obtain a `T` back is [`into_inner`],
/// and the only way to obtain a [`Verified`]-tagged blob is the hash-checking
/// [`verify`] constructor — so the tier on a `Blob` always reflects a real
/// integrity check (or its honest absence).
///
/// [`into_inner`]: Blob::into_inner
/// [`verify`]: Blob::verify
#[derive(Debug)]
pub struct Blob<S: Integrity, T = axum::body::Bytes> {
    payload: T,
    _tier: PhantomData<S>,
}

impl<S: Integrity, T> Blob<S, T> {
    /// The tier name (`"verified"`, `"tamper-evident"`, `"unverified"`).
    #[must_use]
    pub fn tier(&self) -> &'static str {
        S::TIER
    }

    /// Borrow the payload without consuming the witness.
    #[must_use]
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Consume the witness and return the payload.
    ///
    /// This is the *only* way out of a `Blob`, so an `into_inner` at a serve
    /// site is the single auditable point where a tier guarantee is discharged.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.payload
    }
}

impl<T> Blob<Unverified, T> {
    /// Tag raw bytes as [`Unverified`]. Always available — making "I have not
    /// checked these" the easy, honest default.
    #[must_use]
    pub fn raw(payload: T) -> Self {
        Self {
            payload,
            _tier: PhantomData,
        }
    }
}

impl<T> Blob<TamperEvident, T> {
    /// Tag bytes as [`TamperEvident`]: the caller asserts they were produced by
    /// a streaming verifier that checks the digest at EOF (the docker
    /// `VerifyingReader` path). Weaker than [`Verified`] by construction — the
    /// bytes may already be on the wire when a mismatch is detected — which is
    /// exactly why it is a *distinct* tier the type system will not let you pass
    /// where [`Verified`] is required.
    #[must_use]
    pub fn from_eof_verifier(payload: T) -> Self {
        Self {
            payload,
            _tier: PhantomData,
        }
    }
}

impl<T: AsRef<[u8]>> Blob<Verified, T> {
    /// Mint a [`Verified`] blob, or fail.
    ///
    /// Computes `sha256(payload)` and compares it to `expected_sha256_hex`
    /// (case-insensitive, optional `sha256:` prefix). On match, returns the blob
    /// — and possessing it is a *proof* that the bytes hash to `expected`. On
    /// mismatch, returns [`IntegrityError::DigestMismatch`] and **no witness is
    /// produced**: there is no way to obtain a `Blob<Verified>` for bytes that
    /// failed the check.
    ///
    /// This is the parse-don't-validate / smart-constructor pattern: the type
    /// `Blob<Verified>` cannot exist without the check having succeeded.
    pub fn verify(payload: T, expected_sha256_hex: &str) -> Result<Self, IntegrityError> {
        use sha2::{Digest, Sha256};
        let expected = expected_sha256_hex
            .strip_prefix("sha256:")
            .unwrap_or(expected_sha256_hex)
            .to_ascii_lowercase();
        let actual = hex::encode(Sha256::digest(payload.as_ref()));
        if actual == expected {
            Ok(Self {
                payload,
                _tier: PhantomData,
            })
        } else {
            Err(IntegrityError::DigestMismatch { expected, actual })
        }
    }
}

/// Verification failed while trying to mint a [`Verified`] blob.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IntegrityError {
    /// The bytes did not hash to the expected digest.
    #[error("integrity verification failed: expected {expected}, got {actual}")]
    DigestMismatch {
        /// The digest the caller expected (lowercase hex, no prefix).
        expected: String,
        /// The digest the bytes actually produced (lowercase hex).
        actual: String,
    },
}

/// The honest outcome of a buffered, integrity-gated read
/// ([`Storage::get_verified`](crate::storage::Storage::get_verified)).
///
/// A caller cannot get bytes out without `match`ing, so the open-world hole is
/// impossible to ignore: either the bytes matched a recorded pin
/// ([`Verified`](GateOutcome::Verified)), or no pin existed for the key and they
/// were served without a cryptographic check ([`Unpinned`](GateOutcome::Unpinned))
/// — the latter covers both genuinely-unpinned keys and the S3 backend, which
/// has no pin store at all.
#[derive(Debug)]
pub enum GateOutcome<T = axum::body::Bytes> {
    /// A pin existed and the bytes matched it: cryptographically [`Verified`].
    Verified(Blob<Verified, T>),
    /// No pin existed for this key — served open-world (no cryptographic
    /// guarantee). The honest name for the gate's no-pin / S3 branch.
    Unpinned(Blob<Unverified, T>),
}

impl<T> GateOutcome<T> {
    /// `true` if the read was cryptographically verified against a pin.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, GateOutcome::Verified(_))
    }

    /// Discharge the witness to the raw payload, *accepting* the open-world
    /// case. Naming it `accept_open_world` (rather than a silent `unwrap`) keeps
    /// the decision visible at the call site.
    #[must_use]
    pub fn accept_open_world(self) -> T {
        match self {
            GateOutcome::Verified(b) => b.into_inner(),
            GateOutcome::Unpinned(b) => b.into_inner(),
        }
    }
}

/// A serve sink that accepts **only** cryptographically [`Verified`] bytes.
///
/// Routing a response body through this function makes "serve unverified bytes
/// on the verified path" a compile error: a [`Blob<Unverified>`](Blob) or
/// [`Blob<TamperEvident>`](Blob) simply does not fit the parameter. It is the
/// type-level counterpart of the runtime fail-closed gate.
///
/// # The verified path type-checks
///
/// ```
/// use nora_registry::verified::{verified_body, Blob, Verified};
/// // sha256("abc")
/// let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
/// let blob = Blob::<Verified, _>::verify(b"abc".to_vec(), digest).unwrap();
/// assert_eq!(verified_body(blob), b"abc".to_vec());
/// ```
///
/// # Raw bytes do NOT compile on the verified path
///
/// ```compile_fail
/// use nora_registry::verified::{verified_body, Blob};
/// let raw = Blob::raw(b"abc".to_vec());
/// let _ = verified_body(raw); // expected Blob<Verified>, found Blob<Unverified>
/// ```
///
/// # Tamper-evident (streamed) bytes do NOT compile either
///
/// ```compile_fail
/// use nora_registry::verified::{verified_body, Blob};
/// let te = Blob::from_eof_verifier(b"abc".to_vec());
/// let _ = verified_body(te); // expected Blob<Verified>, found Blob<TamperEvident>
/// ```
///
/// # A `Verified` witness cannot be forged
///
/// There is no non-checking constructor, and the payload field is private, so
/// the hash-checking [`Blob::<Verified>::verify`] is the only way in:
///
/// ```compile_fail
/// use nora_registry::verified::{Blob, Verified};
/// let _: Blob<Verified, Vec<u8>> = Blob::raw(b"abc".to_vec()); // raw is Unverified
/// ```
#[must_use]
pub fn verified_body<T>(blob: Blob<Verified, T>) -> T {
    blob.into_inner()
}

// ---------------------------------------------------------------------------
// Write-side witness: "store unpinned" — the S3 hole, named in the type.
// ---------------------------------------------------------------------------

/// Durability tier of a completed store. Sealed, like [`Integrity`].
pub trait Durability: sealed::Sealed {
    /// Short tier name.
    const TIER: &'static str;
}

/// Body **and** hash-pin both landed durably — the local-backend store path.
/// Uninhabited.
#[derive(Debug)]
pub enum Pinned {}

/// Stored on a backend with no pin store (S3): integrity cannot be recorded, so
/// the artifact is served open-world. Names the documented S3 limitation in the
/// type system. Uninhabited.
#[derive(Debug)]
pub enum Unpinnable {}

impl sealed::Sealed for Pinned {}
impl sealed::Sealed for Unpinnable {}
impl Durability for Pinned {
    const TIER: &'static str = "pinned";
}
impl Durability for Unpinnable {
    const TIER: &'static str = "unpinnable";
}

/// Receipt for a completed [`Storage::put`](crate::storage::Storage::put),
/// carrying the [`Durability`] tier it achieved.
#[derive(Debug)]
pub struct StoreReceipt<P: Durability> {
    key: String,
    _tier: PhantomData<P>,
}

impl<P: Durability> StoreReceipt<P> {
    /// The storage key that was written.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
    /// The durability tier name.
    #[must_use]
    pub fn tier(&self) -> &'static str {
        P::TIER
    }
}

impl StoreReceipt<Pinned> {
    /// Mint a [`Pinned`] receipt — call only after both the body and the
    /// hash-pin have durably landed (the local-backend `put` path).
    #[must_use]
    pub fn pinned(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            _tier: PhantomData,
        }
    }
}

impl StoreReceipt<Unpinnable> {
    /// Mint an [`Unpinnable`] receipt — the backend has no pin store (S3).
    #[must_use]
    pub fn unpinnable(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            _tier: PhantomData,
        }
    }
}

/// An operation that requires a durable integrity pin (e.g. an immutable
/// publish that must be re-verifiable). Accepts **only** a
/// [`StoreReceipt<Pinned>`] — passing an [`StoreReceipt<Unpinnable>`] (an S3
/// store) is a compile error, so the S3 hole cannot be silently relied upon.
///
/// # A pinned store type-checks
///
/// ```
/// use nora_registry::verified::{require_pinned, StoreReceipt};
/// let local = StoreReceipt::pinned("raw/x");
/// assert_eq!(require_pinned(local), "raw/x");
/// ```
///
/// # An unpinnable (S3) store does NOT compile here
///
/// ```compile_fail
/// use nora_registry::verified::{require_pinned, StoreReceipt};
/// let s3 = StoreReceipt::unpinnable("raw/x");
/// let _ = require_pinned(s3); // expected StoreReceipt<Pinned>, found <Unpinnable>
/// ```
pub fn require_pinned(receipt: StoreReceipt<Pinned>) -> String {
    receipt.key
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sha_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[test]
    fn verify_mints_on_match() {
        let data = b"hello-world".to_vec();
        let blob = Blob::<Verified, _>::verify(data.clone(), &sha_hex(&data))
            .expect("matching digest must mint a Verified blob");
        assert_eq!(blob.tier(), "verified");
        assert_eq!(verified_body(blob), data);
    }

    #[test]
    fn verify_accepts_sha256_prefix_and_uppercase() {
        let data = b"prefixed".to_vec();
        let with_prefix = format!("sha256:{}", sha_hex(&data).to_uppercase());
        assert!(Blob::<Verified, _>::verify(data, &with_prefix).is_ok());
    }

    #[test]
    fn verify_refuses_on_mismatch() {
        let data = b"genuine".to_vec();
        let wrong = sha_hex(b"tampered");
        let err = Blob::<Verified, _>::verify(data, &wrong).unwrap_err();
        match err {
            IntegrityError::DigestMismatch { expected, actual } => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, sha_hex(b"genuine"));
            }
        }
    }

    #[test]
    fn raw_and_tamper_evident_carry_their_tiers() {
        assert_eq!(Blob::raw(b"x".to_vec()).tier(), "unverified");
        assert_eq!(
            Blob::from_eof_verifier(b"x".to_vec()).tier(),
            "tamper-evident"
        );
    }

    #[test]
    fn gate_outcome_forces_open_world_to_be_visible() {
        let data = b"payload".to_vec();
        let verified = GateOutcome::Verified(
            Blob::<Verified, _>::verify(data.clone(), &sha_hex(&data)).unwrap(),
        );
        assert!(verified.is_verified());
        assert_eq!(verified.accept_open_world(), data);

        let open: GateOutcome<Vec<u8>> = GateOutcome::Unpinned(Blob::raw(b"no-pin".to_vec()));
        assert!(!open.is_verified());
        assert_eq!(open.accept_open_world(), b"no-pin".to_vec());
    }

    #[test]
    fn store_receipt_tiers() {
        assert_eq!(StoreReceipt::pinned("raw/a").tier(), "pinned");
        assert_eq!(StoreReceipt::unpinnable("raw/b").tier(), "unpinnable");
        assert_eq!(require_pinned(StoreReceipt::pinned("raw/c")), "raw/c");
    }
}
