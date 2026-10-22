// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Where an upstream's URL ends in a document, and the rewrite of its occurrences there. Defined
//! once here, for the server's rewrites and for the fuzz targets alike.

/// Whether `rest`, what follows a match of an upstream URL in a document, ends that URL, so the
/// match names the upstream's host and path and not a longer one. The host and each path segment
/// of a URL end at `/`, `?`, `#`, `\` (read as `/` by URL parsers, and the start of every JSON
/// escape such as `\/` or `\"`) or the end of the URL; in a JSON document a URL string also
/// ends at `"`. Anything else continues it — `.` or a letter a longer host or segment, `:` a
/// port, `@` credentials before another host — and names somewhere else.
pub fn ends(rest: &[u8]) -> bool {
    matches!(rest.first(), None | Some(b'/' | b'?' | b'#' | b'\\' | b'"'))
}

/// Every occurrence of the upstream URL `from` in `data` replaced by `to`, where it ends there
/// ([`ends`]). A `from` ending in `/` ends a segment itself.
pub fn replace(data: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return data.to_vec();
    }
    let finder = memchr::memmem::Finder::new(from);
    let mut result = Vec::with_capacity(data.len());
    let mut start = 0;
    let mut search = 0;
    while let Some(pos) = finder.find(&data[search..]).map(|pos| search + pos) {
        let end = pos + from.len();
        if from.ends_with(b"/") || ends(&data[end..]) {
            result.extend_from_slice(&data[start..pos]);
            result.extend_from_slice(to);
            start = end;
            search = end;
        } else {
            search = pos + 1;
        }
    }
    result.extend_from_slice(&data[start..]);
    result
}

/// [`replace`] over text.
pub fn replace_str(text: &str, from: &str, to: &str) -> String {
    // Splits only around whole occurrences of `from`, so the text stays UTF-8.
    String::from_utf8_lossy(&replace(text.as_bytes(), from.as_bytes(), to.as_bytes())).into_owned()
}

/// Whether `data` names the upstream at `upstream`: an occurrence of it that ends there.
pub fn named_in(data: &[u8], upstream: &[u8]) -> bool {
    !upstream.is_empty()
        && memchr::memmem::find_iter(data, upstream).any(|pos| ends(&data[pos + upstream.len()..]))
}

#[cfg(test)]
mod tests {
    use super::named_in;

    /// The fuzz oracle: the upstream is named where its URL ends, and only there.
    #[test]
    fn an_upstream_is_named_only_where_its_url_ends() {
        let up = b"https://up.invalid";
        for named in [
            &b"https://up.invalid"[..],
            b"x https://up.invalid/a",
            b"\"https://up.invalid\"",
            b"https://up.invalid?q",
            b"https://up.invalid#f",
            b"https://up.invalid\\/a",
            b"https://up.invalid.x https://up.invalid/",
        ] {
            assert!(named_in(named, up), "{}", String::from_utf8_lossy(named));
        }
        for other in [
            &b""[..],
            b"https://up.invalid.evil/a",
            b"https://up.invalid:8443/a",
            b"https://up.invalid@evil/a",
            b"https://up.invalidx",
        ] {
            assert!(!named_in(other, up), "{}", String::from_utf8_lossy(other));
        }
        assert!(!named_in(b"anything", b""));
    }
}
