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
use std::sync::Arc;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// The text that replaces a URL's userinfo.
const MASK: &[u8] = b"***";

/// Userinfo the filter cannot find by reading a URL, masked wherever it appears: one set per
/// process, made with its log layers ([`layer`]) and filled from the configured upstreams once
/// the configuration is read ([`KnownTexts::mask_also`]).
#[derive(Clone, Default)]
pub(crate) struct KnownTexts(Arc<parking_lot::RwLock<Vec<Vec<u8>>>>);

impl KnownTexts {
    /// Mask `texts` too, wherever they appear in a line, from now on: the userinfo of
    /// configured upstreams that [`redact_userinfo`] cannot find
    /// ([`crate::url_userinfo::texts_the_filter_misses`]). Adds to what was set before.
    pub(crate) fn mask_also(&self, texts: impl IntoIterator<Item = String>) {
        let mut known = self.0.write();
        known.extend(
            texts
                .into_iter()
                .filter(|t| !t.is_empty())
                .map(String::into_bytes),
        );
        // Longest first, so a text that holds another is masked whole.
        known.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        known.dedup();
    }

    /// `text` as a line is written: the known texts masked, then the userinfo of every URL
    /// ([`redact_userinfo`]).
    pub(crate) fn redact_line<'a>(&self, text: &'a [u8]) -> Cow<'a, [u8]> {
        let known = self.0.read();
        let mut current: Cow<'a, [u8]> = Cow::Borrowed(text);
        for secret in known.iter() {
            if find(&current, secret).is_some() {
                current = Cow::Owned(replace_all(&current, secret, MASK));
            }
        }
        match current {
            Cow::Borrowed(text) => redact_userinfo(text),
            Cow::Owned(owned) => Cow::Owned(redact_userinfo(&owned).into_owned()),
        }
    }

    /// `text` (an error or a message written outside the log) as a log line is written.
    pub(crate) fn redact_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        match self.redact_line(text.as_bytes()) {
            Cow::Borrowed(_) => Cow::Borrowed(text),
            Cow::Owned(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn replace_all(text: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while let Some(at) = find(&text[i..], from) {
        out.extend_from_slice(&text[i..i + at]);
        out.extend_from_slice(to);
        i += at + from.len();
    }
    out.extend_from_slice(&text[i..]);
    out
}

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
pub(crate) fn layer<S, M>(
    json: bool,
    writer: M,
    known: KnownTexts,
) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    M: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let writer = RedactUserinfo(writer, known);
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

/// A [`MakeWriter`] whose writers pass every event through [`KnownTexts::redact_line`].
#[derive(Clone)]
struct RedactUserinfo<M>(M, KnownTexts);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactUserinfo<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter(self.0.make_writer(), self.1.clone())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        RedactingWriter(self.0.make_writer_for(meta), self.1.clone())
    }
}

/// Writes the redacted form of each buffer in full, so the caller's `write_all` never
/// splits an event (and with it a URL) across two calls.
struct RedactingWriter<W>(W, KnownTexts);

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_all(&self.1.redact_line(buf))?;
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
        // As the server does once its configuration is read.
        let known = KnownTexts::default();
        known.mask_also(
            crate::url_userinfo::FORMS
                .iter()
                .flat_map(|(form, _)| crate::url_userinfo::texts_the_filter_misses(form)),
        );
        let redact = |text: &str| {
            String::from_utf8(known.redact_line(text.as_bytes()).into_owned()).unwrap()
        };
        for (form, secrets) in crate::url_userinfo::FORMS {
            for line in [
                form.to_string(),
                format!("url={form} status=502"),
                format!(r#"{{"url":"{form}","n":1}}"#),
                format!("\x1b[2m=\x1b[0m{form}"),
                format!("upstream maven:{form} temporarily unavailable"),
                format!("error sending request for url ({form})"),
                // A JSON log line escapes the URL: `"` and `\` are written with a `\`.
                format!(r#"{{"url":{}}}"#, serde_json::to_string(form).unwrap()),
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

    /// An upstream configured as an address the parser cannot read but with an `@` is masked
    /// whole in every line that holds it, a request URL built on it included: a handler logs
    /// the URL it asked as it is (`url = %url`), and the filter finds no URL in it.
    #[test]
    fn an_unreadable_configured_address_is_masked_whole() {
        use crate::url_userinfo::check::holds_no_secret;
        // Its own text: the known texts are shared by the tests of this process.
        let configured = "robot:t0ken-unread@other.example";
        let known = KnownTexts::default();
        known.mask_also(crate::url_userinfo::texts_the_filter_misses(configured));
        for line in [
            format!("ERROR Failed to send request to upstream url={configured}/v2/library/a"),
            format!(r#"{{"fields":{{"url":"{configured}/v2/x"}}}}"#),
        ] {
            let out = String::from_utf8(known.redact_line(line.as_bytes()).into_owned()).unwrap();
            holds_no_secret(&out, configured, &["robot", "t0ken-unread"]);
            assert!(out.contains("***"), "{out}");
        }
    }

    /// A known text that holds another is masked whole, not around the one it holds.
    #[test]
    fn a_known_text_holding_another_is_masked_whole() {
        let known = KnownTexts::default();
        known.mask_also(["q7 u".to_string(), "q7 u v".to_string()]);
        let out = known.redact_line(b"user=q7 u v end");
        assert_eq!(String::from_utf8(out.into_owned()).unwrap(), "user=*** end");
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

    /// Every form an upstream may be configured in, readable or not, in every spelling an
    /// output takes it in (`%` and `?` fields, a message with `{}` and `{:?}`), through every
    /// output (the log as text, the log as JSON, stderr), as the server masks once its
    /// configuration is read: no user or password, in any spelling, reaches the output. The
    /// address is logged as a request URL built on it, as a handler logs the URL it asked.
    #[test]
    fn every_form_in_every_spelling_is_masked_in_every_output() {
        use crate::url_userinfo::{check::holds_no_spelling, FORMS, UNREADABLE_FORMS};
        use tracing_subscriber::prelude::*;
        for (form, secrets) in FORMS.iter().chain(UNREADABLE_FORMS) {
            let known = KnownTexts::default();
            known.mask_also(crate::url_userinfo::texts_the_filter_misses(form));
            let url = format!("{form}/pkg/-/pkg-1.0.0.tgz");
            for json in [false, true] {
                let sink = Captured::default();
                let subscriber =
                    tracing_subscriber::registry().with(layer(json, sink.clone(), known.clone()));
                tracing::subscriber::with_default(subscriber, || {
                    tracing::warn!(url = %url, "upstream failed");
                    tracing::warn!(url = ?url, "upstream failed");
                    tracing::warn!("upstream {url} failed");
                    tracing::warn!("upstream {url:?} failed");
                    // As a client error names it: the client's own spelling of the address.
                    if let Ok(asked) = reqwest::Url::parse(&url) {
                        tracing::warn!("builder error for url ({asked})");
                    }
                });
                let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
                assert!(out.lines().count() >= 4, "{out}");
                holds_no_spelling(&out, form, secrets);
            }
            for stderr in [format!("nora: {url}"), format!("nora: {url:?}")] {
                holds_no_spelling(&known.redact_text(&stderr), form, secrets);
            }
        }
    }

    /// End to end through the layer the server builds, JSON and text: the secret of a
    /// `Display` field, a `Debug` field and the message never reaches the writer.
    #[test]
    fn a_log_layer_never_emits_the_secret() {
        use tracing_subscriber::prelude::*;
        for json in [true, false] {
            let sink = Captured::default();
            emit(tracing_subscriber::registry().with(layer(
                json,
                sink.clone(),
                KnownTexts::default(),
            )));
            assert_clean(&sink);
        }
    }
}
