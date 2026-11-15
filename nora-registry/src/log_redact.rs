//! Log output never carries the userinfo of a URL.
//!
//! An upstream may be configured as `https://user:secret@host/…`, and its URL reaches
//! log fields in dozens of places (request URL, upstream name, retry and error lines).
//! Fixing each call site leaves the next new log line to leak, so the formatted event
//! is cleaned in one place instead: every `fmt` layer is built by [`layer`], which writes
//! through [`RedactUserinfo`].
//! `tracing-subscriber` formats a whole event into one buffer and hands it to the
//! writer with a single `write_all`, so each write here sees complete lines.

use serde::{Deserialize, Deserializer, Serialize};
use std::borrow::Cow;
use std::io;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// The text that replaces a URL's userinfo.
const MASK: &[u8] = b"***";

/// Replace the userinfo of every `scheme://userinfo@host` in `text` with [`MASK`].
///
/// The authority ends at the first `/`, `?`, `#`, whitespace, quote, backslash or
/// bracket after `://` (a JSON string, a `Debug` string and prose all end a URL that
/// way); an `@` inside it marks userinfo, and everything up to the last such `@` is
/// masked. Text without userinfo is returned unchanged and unallocated.
pub(crate) fn redact_userinfo(text: &[u8]) -> Cow<'_, [u8]> {
    let mut out: Option<Vec<u8>> = None;
    let mut copied = 0;
    let mut i = 0;
    while let Some(pos) = find(&text[i..], b"://") {
        let start = i + pos + 3;
        let end = text[start..]
            .iter()
            .position(|&b| {
                matches!(
                    b,
                    b'/' | b'?' | b'#' | b'"' | b'\'' | b'\\' | b'<' | b'>' | b'(' | b')'
                ) || b.is_ascii_whitespace()
            })
            .map_or(text.len(), |n| start + n);
        if let Some(at) = text[start..end].iter().rposition(|&b| b == b'@') {
            let buf = out.get_or_insert_with(|| Vec::with_capacity(text.len()));
            buf.extend_from_slice(&text[copied..start]);
            buf.extend_from_slice(MASK);
            copied = start + at;
        }
        i = end;
    }
    match out {
        Some(mut buf) => {
            buf.extend_from_slice(&text[copied..]);
            Cow::Owned(buf)
        }
        None => Cow::Borrowed(text),
    }
}

/// A URL as NORA writes it down outside the log — a journal record — in the form every log
/// line has it: userinfo replaced by [`MASK`], the rest kept. The query is kept too, as in the
/// log: a credential belongs in userinfo or a header, and a query is part of what names the
/// file.
pub(crate) fn url_for_record(url: &str) -> Cow<'_, str> {
    match redact_userinfo(url.as_bytes()) {
        Cow::Borrowed(_) => Cow::Borrowed(url),
        // Only ASCII between ASCII delimiters is replaced, so the text stays UTF-8.
        Cow::Owned(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
    }
}

/// A URL as a record keeps it: built only through [`url_for_record`], from a URL being recorded
/// ([`RecordedUrl::new`]) and from one read back from a record (its `Deserialize`), so no
/// record holds userinfo, a line written before masking included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RecordedUrl(String);

impl RecordedUrl {
    /// `url` with its userinfo masked.
    pub fn new(url: &str) -> Self {
        Self(url_for_record(url).into_owned())
    }

    /// The URL as recorded.
    #[cfg(test)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for RecordedUrl {
    fn from(url: &str) -> Self {
        Self::new(url)
    }
}

impl<'de> Deserialize<'de> for RecordedUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|url| Self::new(&url))
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A `fmt` layer writing `writer`'s events through [`RedactUserinfo`]: JSON with each event's
/// target, or text without. The one way the server builds a log layer, stdout and file alike;
/// the redacting writer cannot be made or unwrapped outside this module.
pub(crate) fn layer<S, M>(json: bool, writer: M) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    M: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let writer = RedactUserinfo(writer);
    if json {
        tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_writer(writer)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_writer(writer)
            .boxed()
    }
}

/// A [`MakeWriter`] whose writers pass every event through [`redact_userinfo`].
#[derive(Clone, Copy)]
struct RedactUserinfo<M>(M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactUserinfo<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter(self.0.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        RedactingWriter(self.0.make_writer_for(meta))
    }
}

/// Writes the redacted form of each buffer in full, so the caller's `write_all` never
/// splits an event (and with it a URL) across two calls.
struct RedactingWriter<W>(W);

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_all(&redact_userinfo(buf))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn redact(text: &str) -> String {
        String::from_utf8(redact_userinfo(text.as_bytes()).into_owned()).unwrap()
    }

    #[test]
    fn userinfo_is_masked_in_every_url_of_a_line() {
        assert_eq!(
            redact(r#"{"url":"https://user:secret@host/v2/x","upstream":"http://tok@h:5000"}"#),
            r#"{"url":"https://***@host/v2/x","upstream":"http://***@h:5000"}"#
        );
        assert_eq!(
            redact("fetch http://u:p@a.example?x=1 and https://b:q@c.example#f"),
            "fetch http://***@a.example?x=1 and https://***@c.example#f"
        );
        // A Debug-formatted field escapes its quotes: the backslash ends the authority.
        assert_eq!(
            redact(r#"url=\"https://u:p@h\" end"#),
            r#"url=\"https://***@h\" end"#
        );
        // The last @ of the authority is the delimiter: an @ in the password is masked too.
        assert_eq!(redact("https://u:p@ss@host/x"), "https://***@host/x");
        assert_eq!(redact("https://u:secret@host"), "https://***@host");
    }

    #[test]
    fn text_without_userinfo_is_untouched_and_not_copied() {
        for text in [
            "https://host/path/user@example",
            "email user@example.com and https://host:8443/x",
            "no url at all",
            "trailing ://",
            // A JSON escape ends the authority: the host is not mistaken for userinfo.
            r"https://host\nuser@example",
            "",
        ] {
            assert!(
                matches!(redact_userinfo(text.as_bytes()), Cow::Borrowed(_)),
                "{text}"
            );
        }
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn emit(subscriber: impl tracing::Subscriber + Send + Sync) {
        tracing::subscriber::with_default(subscriber, || {
            let url = "https://user:canary-secret@registry.example/v2/x";
            tracing::warn!(url = %url, upstream = ?url, "fetch {url} failed");
        });
    }

    fn assert_clean(sink: &Captured) {
        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("registry.example"), "{out}");
        assert!(!out.contains("canary-secret"), "{out}");
        assert!(!out.contains("user:"), "{out}");
    }

    /// End to end through the layer the server builds, JSON and text: the secret of a
    /// `Display` field, a `Debug` field and the message never reaches the writer.
    #[test]
    fn a_log_layer_never_emits_the_secret() {
        use tracing_subscriber::prelude::*;
        for json in [true, false] {
            let sink = Captured::default();
            emit(tracing_subscriber::registry().with(layer(json, sink.clone())));
            assert_clean(&sink);
        }
    }
}
