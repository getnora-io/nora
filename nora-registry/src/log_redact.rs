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

/// Replace the userinfo of every URL in `text` with [`MASK`].
///
/// A URL is found where the proxy client's parser (`reqwest::Url`) would find its authority:
/// after `http:` or `https:` in any letter case and any run of `/` and `\`
/// (`https:///user:secret@host` and `https:/user:secret@host` are read as userinfo for
/// `host`), and after `://` for any other scheme. What precedes the scheme is not read: a
/// colored log line puts an escape code right before it (`\x1b[0mhttps://…`). The authority ends at the first `/`, `\`,
/// `?` or `#`, as the parser ends it, or at whitespace, `"`, `<` or `>`, which a URL in a
/// log line, a JSON string or a `Debug` string does not hold unescaped; an `@` inside it
/// marks userinfo, and everything up to the last such `@` is masked. `'`, `(` and `)` may
/// stand in a password unescaped and do not end it. Text without userinfo is returned
/// unchanged and unallocated. Which spellings the parser reads as userinfo is pinned by the
/// table of [`crate::url_userinfo::FORMS`].
pub(crate) fn redact_userinfo(text: &[u8]) -> Cow<'_, [u8]> {
    let mut out: Option<Vec<u8>> = None;
    let mut copied = 0;
    let mut i = 0;
    while let Some(colon) = text[i..].iter().position(|&b| b == b':').map(|p| i + p) {
        let Some(start) = authority_start(text, colon) else {
            i = colon + 1;
            continue;
        };
        let end = text[start..]
            .iter()
            .position(|&b| {
                matches!(b, b'/' | b'\\' | b'?' | b'#' | b'"' | b'<' | b'>')
                    || b.is_ascii_whitespace()
            })
            .map_or(text.len(), |n| start + n);
        if let Some(at) = text[start..end].iter().rposition(|&b| b == b'@') {
            let buf = out.get_or_insert_with(|| Vec::with_capacity(text.len()));
            buf.extend_from_slice(&text[copied..start]);
            buf.extend_from_slice(MASK);
            copied = start + at;
        }
        i = end.max(colon + 1);
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
    crate::url_userinfo::masked(url)
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

/// Where the authority of a URL whose scheme ends at `colon` starts, if `colon` ends one:
/// after the run of `/` and `\` that follows `http:` or `https:`, after `//` otherwise.
fn authority_start(text: &[u8], colon: usize) -> Option<usize> {
    let rest = &text[colon + 1..];
    let before = &text[..colon];
    let special = [&b"http"[..], b"https"].iter().any(|s| {
        before.len() >= s.len() && before[before.len() - s.len()..].eq_ignore_ascii_case(s)
    });
    if special {
        // The parser skips every `/` and `\` between a special scheme and its authority.
        let slashes = rest
            .iter()
            .position(|&b| b != b'/' && b != b'\\')
            .unwrap_or(rest.len());
        Some(colon + 1 + slashes)
    } else if rest.starts_with(b"//") {
        Some(colon + 3)
    } else {
        None
    }
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

    /// Every spelling the client reads userinfo in, wherever a log line holds it: alone, as a
    /// field, in a JSON string, after a color code, as a breaker key, in prose. Alone, it still
    /// names the target the client sends to, with `***` as its only user.
    #[test]
    fn every_form_the_client_reads_is_masked_in_a_line() {
        use crate::url_userinfo::check::{holds_no_secret, same_target};
        for (form, secrets) in crate::url_userinfo::FORMS {
            for line in [
                form.to_string(),
                format!("url={form} status=502"),
                format!(r#"{{"url":"{form}","n":1}}"#),
                format!("\x1b[2m=\x1b[0m{form}"),
                format!("upstream maven:{form} temporarily unavailable"),
                format!("error sending request for url ({form})"),
            ] {
                holds_no_secret(&redact(&line), form, secrets);
            }
            let alone = redact(form);
            same_target(&alone, form);
            let parsed = reqwest::Url::parse(&alone).unwrap();
            assert_eq!(
                (parsed.username(), parsed.password()),
                ("***", None),
                "{form}"
            );
        }
    }

    /// A record of each spelling, written or read back from a journal line written before
    /// masking, holds none of its userinfo.
    #[test]
    fn every_form_is_masked_in_a_record() {
        use crate::url_userinfo::check::holds_no_secret;
        for (form, secrets) in crate::url_userinfo::FORMS {
            let written = serde_json::to_string(&RecordedUrl::new(form)).unwrap();
            holds_no_secret(&written, form, secrets);
            let line = serde_json::to_string(form).unwrap();
            let read: RecordedUrl = serde_json::from_str(&line).unwrap();
            holds_no_secret(read.as_str(), form, secrets);
        }
        for unreadable in ["https://ci-bot:pa/ss@mirror.example", "ci-bot:s3cr3t@host"] {
            assert_eq!(RecordedUrl::new(unreadable).as_str(), "***", "{unreadable}");
        }
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
