// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Serialize, Serializer};
use std::cmp::Ordering;
use std::collections::BTreeMap;

const HEADER_PREFIX: &str = "x-nora-meta-";

const PIN_METADATA_KEY: &str = "sha256";
const PIN_METADATA_LEN: usize = PIN_METADATA_KEY.len() + 64;
const S3_USER_METADATA_CAP: usize = 2048;
const MAX_KEY_LEN: usize = 64;
const MAX_VALUE_LEN: usize = 1024;
const MAX_COUNT: usize = 32;
const MAX_TOTAL_LEN: usize = S3_USER_METADATA_CAP - PIN_METADATA_LEN;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Annotations(BTreeMap<AnnotationKey, String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnotationKey(HeaderName);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnnotationError {
    #[error("annotation key {0:?} must be 1 to {max} characters from a-z, 0-9 and -", max = MAX_KEY_LEN)]
    BadKey(String),
    #[error("annotation key {PIN_METADATA_KEY:?} is reserved for the integrity pin")]
    ReservedKey,
    #[error("annotation {0:?} must have one value of 1 to {max} printable ASCII characters", max = MAX_VALUE_LEN)]
    BadValue(String),
    #[error("at most {max} annotations are allowed, the request has {0}", max = MAX_COUNT)]
    TooMany(usize),
    #[error("annotation keys and values must total at most {max} bytes, the request has {0}", max = MAX_TOTAL_LEN)]
    TooLarge(usize),
}

impl AnnotationKey {
    fn parse(key: &str) -> Result<Self, AnnotationError> {
        let bad = || AnnotationError::BadKey(key.to_string());
        if !(1..=MAX_KEY_LEN).contains(&key.len())
            || !key
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(bad());
        }
        if key == PIN_METADATA_KEY {
            return Err(AnnotationError::ReservedKey);
        }
        HeaderName::try_from(format!("{HEADER_PREFIX}{key}"))
            .map(Self)
            .map_err(|_| bad())
    }

    pub fn as_str(&self) -> &str {
        &self.0.as_str()[HEADER_PREFIX.len()..]
    }

    pub fn header_name(&self) -> &HeaderName {
        &self.0
    }
}

impl Ord for AnnotationKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for AnnotationKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for AnnotationKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

fn parse_value(key: &AnnotationKey, value: &str) -> Result<String, AnnotationError> {
    if (1..=MAX_VALUE_LEN).contains(&value.len())
        && value.bytes().all(|b| (0x20..=0x7E).contains(&b))
    {
        Ok(value.to_string())
    } else {
        Err(AnnotationError::BadValue(key.as_str().to_string()))
    }
}

impl Annotations {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, AnnotationError> {
        let mut annotations = Self::default();
        for name in headers.keys() {
            let Some(key) = name.as_str().strip_prefix(HEADER_PREFIX) else {
                continue;
            };
            let key = AnnotationKey::parse(key)?;
            let mut values = headers.get_all(name).iter();
            let value = match (values.next().map(HeaderValue::to_str), values.next()) {
                (Some(Ok(value)), None) => parse_value(&key, value)?,
                _ => return Err(AnnotationError::BadValue(key.as_str().to_string())),
            };
            annotations.insert(key, value);
        }
        annotations.within_limits()
    }

    pub fn try_from_pairs(
        pairs: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, AnnotationError> {
        let mut annotations = Self::default();
        for (key, value) in pairs {
            let key = AnnotationKey::parse(&key)?;
            let value = parse_value(&key, &value)?;
            annotations.insert(key, value);
        }
        annotations.within_limits()
    }

    /// Metadata written to the store out of band can break the rules, and a read must not fail on it.
    pub fn from_stored(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut annotations = Self::default();
        for (key, value) in pairs {
            match AnnotationKey::parse(&key)
                .and_then(|key| parse_value(&key, &value).map(|value| (key, value)))
            {
                Ok((key, value)) => annotations.insert(key, value),
                Err(e) => tracing::debug!(key = %key, error = %e, "object metadata skipped"),
            }
        }
        annotations
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }

    pub fn response_headers(&self) -> impl Iterator<Item = (&HeaderName, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.header_name(), value.as_str()))
    }

    fn insert(&mut self, key: AnnotationKey, value: String) {
        self.0.insert(key, value);
    }

    fn within_limits(self) -> Result<Self, AnnotationError> {
        if self.0.len() > MAX_COUNT {
            return Err(AnnotationError::TooMany(self.0.len()));
        }
        let total: usize = self
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum();
        if total > MAX_TOTAL_LEN {
            return Err(AnnotationError::TooLarge(total));
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::try_from(*name).unwrap(),
                HeaderValue::try_from(*value).unwrap(),
            );
        }
        map
    }

    fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn only_meta_headers_become_annotations() {
        let parsed = Annotations::from_headers(&headers(&[
            ("x-nora-meta-commit", "abc123"),
            ("X-Nora-Meta-Build-Id", "42"),
            ("content-type", "text/plain"),
        ]))
        .unwrap();
        assert_eq!(
            parsed.iter().collect::<Vec<_>>(),
            vec![("build-id", "42"), ("commit", "abc123")]
        );
        let names: Vec<_> = parsed
            .response_headers()
            .map(|(name, value)| (name.as_str(), value))
            .collect();
        assert_eq!(
            names,
            vec![
                ("x-nora-meta-build-id", "42"),
                ("x-nora-meta-commit", "abc123")
            ]
        );
    }

    #[test]
    fn a_key_outside_the_charset_or_in_the_pin_slot_is_refused() {
        for (name, want) in [
            (
                "x-nora-meta-bad_key",
                AnnotationError::BadKey("bad_key".into()),
            ),
            ("x-nora-meta-", AnnotationError::BadKey(String::new())),
            ("x-nora-meta-sha256", AnnotationError::ReservedKey),
        ] {
            assert_eq!(
                Annotations::from_headers(&headers(&[(name, "v")])),
                Err(want),
                "{name}"
            );
        }
        let long = format!("x-nora-meta-{}", "k".repeat(65));
        assert!(matches!(
            Annotations::from_headers(&headers(&[(&long, "v")])),
            Err(AnnotationError::BadKey(_))
        ));
    }

    #[test]
    fn a_value_is_one_printable_ascii_value() {
        let mut map = HeaderMap::new();
        map.insert(
            "x-nora-meta-k",
            HeaderValue::from_bytes("caf\u{e9}".as_bytes()).unwrap(),
        );
        assert_eq!(
            Annotations::from_headers(&map),
            Err(AnnotationError::BadValue("k".into()))
        );
        for value in ["", "a\tb", &"v".repeat(1025)] {
            assert_eq!(
                Annotations::try_from_pairs(pairs(&[("k", value)])),
                Err(AnnotationError::BadValue("k".into())),
                "{value:?}"
            );
        }
        assert_eq!(
            Annotations::from_headers(&headers(&[("x-nora-meta-k", "a"), ("x-nora-meta-k", "b")])),
            Err(AnnotationError::BadValue("k".into()))
        );
    }

    #[test]
    fn the_count_and_the_size_are_capped() {
        let many: Vec<_> = (0..33)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        assert_eq!(
            Annotations::try_from_pairs(many),
            Err(AnnotationError::TooMany(33))
        );
        let at_cap: Vec<_> = (0..2)
            .map(|i| (format!("k{i}"), "v".repeat(MAX_TOTAL_LEN / 2 - 2)))
            .collect();
        assert!(Annotations::try_from_pairs(at_cap).is_ok());
        let large: Vec<_> = (0..3)
            .map(|i| (format!("k{i}"), "v".repeat(1000)))
            .collect();
        assert_eq!(
            Annotations::try_from_pairs(large),
            Err(AnnotationError::TooLarge(3006))
        );
    }

    #[test]
    fn stored_metadata_keeps_the_pairs_that_obey_the_rules() {
        let stored =
            Annotations::from_stored(pairs(&[("commit", "abc"), ("Odd Key", "x"), ("empty", "")]));
        assert_eq!(stored.iter().collect::<Vec<_>>(), vec![("commit", "abc")]);
    }

    #[test]
    fn annotations_serialize_as_a_map() {
        let a = Annotations::try_from_pairs(pairs(&[("commit", "abc"), ("a", "1")])).unwrap();
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            r#"{"a":"1","commit":"abc"}"#
        );
    }
}
