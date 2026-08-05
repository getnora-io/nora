// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Shared HTTP Range (RFC 9110 §14) support: parse a single-range `Range`
//! header and serve the 206/416 response from the storage backend's ranged
//! read. Every format handler uses this, so resumable downloads behave the
//! same everywhere.

use crate::storage::Storage;
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio_util::io::ReaderStream;

/// The result of matching a `Range` header against a known object size.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParsedRange {
    /// Inclusive `(start, end)`, clamped to the object.
    Satisfiable(u64, u64),
    /// A well-formed `bytes=` range that starts at or past the end of the
    /// object. RFC 9110 §15.5.17 wants a 416 here: a client that already holds
    /// the whole file resumes with `bytes=<size>-`, and a full 200 would make
    /// it download everything again.
    Unsatisfiable,
    /// Absent, not `bytes=`, multi-range, or unparsable. RFC 9110 §14.2 lets a
    /// server ignore a Range it does not understand, so the caller serves the
    /// full 200.
    None,
}

/// Parse a single `Range: bytes=start-end` header against a known object size.
/// Suffix ranges (`bytes=-N`, the last N bytes) are supported. Multi-range
/// needs a `multipart/byteranges` body, which we do not produce, so it is
/// ignored.
pub(crate) fn parse_byte_range(value: &str, size: u64) -> ParsedRange {
    parse_spec(value, size).unwrap_or(ParsedRange::None)
}

/// Lexer half of [`parse_byte_range`]: `None` means the header is not a single
/// `bytes=` range we can read.
fn parse_spec(value: &str, size: u64) -> Option<ParsedRange> {
    let spec = value.strip_prefix("bytes=")?.trim();
    if spec.contains(',') {
        return None;
    }
    let (s, e) = spec.split_once('-')?;
    if s.is_empty() {
        // suffix form "bytes=-N": the last N bytes
        let n: u64 = e.trim().parse().ok()?;
        Some(byte_range_core(true, 0, false, n, size))
    } else {
        let start: u64 = s.trim().parse().ok()?;
        let (end_empty, end_in) = if e.trim().is_empty() {
            (true, 0)
        } else {
            (false, e.trim().parse::<u64>().ok()?)
        };
        Some(byte_range_core(false, start, end_empty, end_in, size))
    }
}

/// Arithmetic core of [`parse_byte_range`], split out so the out-of-bounds /
/// inverted-range / overflow bug-class can be *proven* absent over the whole
/// `u64` space. String lexing stays in the caller — symbolically lexing a
/// UTF-8 string is intractable for a bounded model checker, while the bounds
/// invariant lives entirely in this arithmetic. For any inputs it never
/// panics/overflows; any `Satisfiable(start, end)` satisfies `start <= end < size`.
fn byte_range_core(
    suffix: bool,
    start_in: u64,
    end_empty: bool,
    end_in: u64,
    size: u64,
) -> ParsedRange {
    if suffix {
        if end_in == 0 {
            return ParsedRange::None;
        }
        if size == 0 {
            return ParsedRange::Unsatisfiable;
        }
        return ParsedRange::Satisfiable(size.saturating_sub(end_in), size - 1);
    }
    if start_in >= size {
        return ParsedRange::Unsatisfiable;
    }
    let end = if end_empty {
        size - 1
    } else {
        end_in.min(size - 1)
    };
    if start_in > end {
        return ParsedRange::None;
    }
    ParsedRange::Satisfiable(start_in, end)
}

/// Kani proof: [`byte_range_core`] is total and bounds-safe. For ANY
/// `(suffix, start_in, end_empty, end_in, size)` over the full `u64` space it
/// never panics or overflows, and any `Satisfiable(start, end)` is well-formed:
/// `start <= end < size` — the whole "out-of-bounds / inverted Range" bug-class
/// discharged at verification time, not at runtime. (Verified GREEN in-crate,
/// 17/17 checks in ~0.3s.)
///
/// Run: `make kani`, or `cargo kani -p nora-registry` (CI: `.github/workflows/kani.yml`).
/// Compiled only under `--cfg kani`; invisible to the normal build/clippy/test.
#[cfg(kani)]
#[kani::proof]
fn byte_range_core_is_bounds_safe() {
    let suffix: bool = kani::any();
    let start_in: u64 = kani::any();
    let end_empty: bool = kani::any();
    let end_in: u64 = kani::any();
    let size: u64 = kani::any();
    if let ParsedRange::Satisfiable(start, end) =
        byte_range_core(suffix, start_in, end_empty, end_in, size)
    {
        assert!(start <= end, "Range start must never exceed end");
        assert!(end < size, "Range end must stay within the object size");
        assert!(start < size, "Range start must stay within the object size");
    }
}

/// Serve a Range request from the backend's ranged read, trying `keys` in order
/// (namespaced key first, legacy key second).
///
/// `None` means no usable Range header, or every ranged read failed — the
/// caller serves the full 200 and must set `Accept-Ranges: bytes` on it. A
/// transient storage error must not turn a resumable download into a 500.
/// `Some` is a finished 206 or 416; return it as is.
///
/// A ranged serve reads part of the object, so it cannot rehash it: there is no
/// server-side integrity check on this path. The client's own checksum (lockfile
/// hash, content digest) covers it — the precedent docker set in #657.
pub(crate) async fn range_response(
    storage: &Storage,
    keys: &[&str],
    headers: &HeaderMap,
    size: u64,
    content_type: &str,
    extra: &[(HeaderName, String)],
) -> Option<Response> {
    let (start, end) = match parse_byte_range(headers.get(header::RANGE)?.to_str().ok()?, size) {
        ParsedRange::Satisfiable(start, end) => (start, end),
        ParsedRange::Unsatisfiable => {
            return Some(
                Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{}", size))
                    .header(header::ACCEPT_RANGES, "bytes")
                    .body(Body::empty())
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            )
        }
        ParsedRange::None => return None,
    };

    let mut reader = None;
    for key in keys {
        if let Ok((_, r)) = storage.get_range(key, start, end).await {
            reader = Some(r);
            break;
        }
    }

    let mut response = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, end - start + 1)
        .header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end, size),
        )
        .header(header::ACCEPT_RANGES, "bytes");
    for (name, value) in extra {
        response = response.header(name, value.as_str());
    }
    Some(
        response
            .body(Body::from_stream(ReaderStream::new(reader?)))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_byte_range, ParsedRange};
    use ParsedRange::{None as Ignore, Satisfiable, Unsatisfiable};

    #[test]
    fn test_parse_byte_range() {
        assert_eq!(parse_byte_range("bytes=0-3", 10), Satisfiable(0, 3));
        assert_eq!(parse_byte_range("bytes=5-", 10), Satisfiable(5, 9)); // open-ended
        assert_eq!(parse_byte_range("bytes=-4", 10), Satisfiable(6, 9)); // suffix (last 4)
        assert_eq!(parse_byte_range("bytes=8-100", 10), Satisfiable(8, 9)); // clamp end to size
        assert_eq!(parse_byte_range("bytes=10-12", 10), Unsatisfiable); // start past end → 416
        assert_eq!(parse_byte_range("bytes=5-3", 10), Ignore); // reversed
        assert_eq!(parse_byte_range("nonsense", 10), Ignore); // unparsable
        assert_eq!(parse_byte_range("bytes=0-1,4-5", 10), Ignore); // multi-range
        assert_eq!(parse_byte_range("bytes=0-3", 0), Unsatisfiable); // empty object

        // A client that already holds the whole file resumes with `bytes=<size>-`
        // and must get a 416, not a full re-download.
        assert_eq!(parse_byte_range("bytes=10-", 10), Unsatisfiable);

        // mutation-found gaps (cargo-mutants): exercise the single-byte range
        // and the suffix form against an empty object.
        assert_eq!(parse_byte_range("bytes=5-5", 10), Satisfiable(5, 5)); // single byte (kills `>`→`>=`)
        assert_eq!(parse_byte_range("bytes=-5", 0), Unsatisfiable); // suffix + empty
    }

    proptest::proptest! {
        /// Property test (#3): fuzz the string LEXER of `parse_byte_range` — the
        /// part Kani cannot symbolically execute. Over biased range-like strings
        /// and any size it must never panic, and any `Satisfiable(s, e)` is
        /// well-formed: `s <= e < size`. Pairs with the Kani proof of
        /// `byte_range_core` (the arithmetic) for full-function coverage.
        #[test]
        fn parse_byte_range_lexer_invariant(
            value in "bytes=-?[0-9]{0,9}-?[0-9]{0,9}",
            size in proptest::prelude::any::<u64>(),
        ) {
            if let Satisfiable(s, e) = parse_byte_range(&value, size) {
                proptest::prop_assert!(s <= e, "inverted: {} > {}", s, e);
                proptest::prop_assert!(e < size, "oob end: {} >= {}", e, size);
                proptest::prop_assert!(s < size, "oob start: {} >= {}", s, size);
            }
        }
    }
}
