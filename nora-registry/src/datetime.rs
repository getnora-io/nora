// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Every date NORA writes or reads, in one place (#1282).
//!
//! The spellings are the ones NORA has always produced and accepted; stores written by earlier
//! releases are read back the same way, and clients see the same bytes. The golden tests
//! (`datetime_golden.rs`, and a corpus under `testdata/datetime/`) pin each spelling and each
//! parser to the values NORA 1.4.5 produced.

use std::fmt;

/// An instant in UTC, to the nanosecond.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTime {
    secs: i64,
    nanos: u32,
}

impl UtcTime {
    /// 1970-01-01T00:00:00Z.
    pub const EPOCH: UtcTime = UtcTime { secs: 0, nanos: 0 };

    /// Now, by the system clock.
    pub fn now() -> UtcTime {
        imp::now()
    }

    /// The instant `secs` seconds and `nanos` nanoseconds after the epoch, if it is within the
    /// representable range (years -262143..=262142) and `nanos` is under a second — or under
    /// two at the last second of a minute, a leap second (`23:59:60`).
    pub fn from_unix(secs: i64, nanos: u32) -> Option<UtcTime> {
        imp::checked(secs, nanos)
    }

    /// Whole seconds since the epoch (rounded down).
    pub fn unix(self) -> i64 {
        self.secs
    }

    /// Nanoseconds past [`UtcTime::unix`].
    pub fn subsec_nanos(self) -> u32 {
        self.nanos
    }

    /// RFC 3339 with `Z` and as many fraction digits as the value needs, in groups of three:
    /// `2026-11-17T08:15:00Z`, `2026-11-17T08:15:00.120Z`, `2026-11-17T08:15:00.123456789Z`.
    /// The JSON form of every serialized time (audit log, activity, backup metadata).
    pub fn rfc3339(self) -> String {
        imp::rfc3339(self, true)
    }

    /// RFC 3339 to the second, with `Z`: `2026-11-17T08:15:00Z` (Docker token `issued_at`).
    pub fn rfc3339_secs(self) -> String {
        imp::rfc3339(self, false)
    }

    /// HTTP-date (RFC 9110 IMF-fixdate): `Tue, 17 Nov 2026 08:15:00 GMT`.
    pub fn http_date(self) -> String {
        imp::imf_date(self, "GMT")
    }

    /// The `Date:` of an apt `Release` file: `Tue, 17 Nov 2026 08:15:00 UTC`.
    pub fn apt_release_date(self) -> String {
        imp::imf_date(self, "UTC")
    }

    /// Maven `lastUpdated`: `20261117081500`.
    pub fn maven_last_updated(self) -> String {
        imp::compact(self)
    }

    /// Composer `time` of a published version: `2026-11-17T08:15:00+00:00`.
    pub fn composer_time(self) -> String {
        imp::composer(self)
    }

    /// Whole seconds from `self` to `later` (negative when `later` is earlier).
    pub fn seconds_until(self, later: UtcTime) -> i64 {
        imp::seconds_between(self, later)
    }
}

/// `2026-11-17 08:15:00.123456789 UTC`, as `backup restore` prints the backup's creation time.
impl fmt::Display for UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&imp::display(*self))
    }
}

impl serde::Serialize for UtcTime {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.rfc3339())
    }
}

impl<'de> serde::Deserialize<'de> for UtcTime {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        parse_rfc3339_relaxed(&s).ok_or_else(|| {
            serde::de::Error::custom(format!("not an RFC 3339 date and time: {s:?}"))
        })
    }
}

/// Seconds since the epoch, now.
pub fn now_unix() -> i64 {
    UtcTime::now().unix()
}

/// Now less `secs` seconds, to the second: the release date tests give a fixture.
#[cfg(test)]
pub fn ago(secs: i64) -> UtcTime {
    UtcTime::from_unix(now_unix() - secs, 0).expect("a test date is in range")
}

/// A serialized time read back: RFC 3339 with the leniency NORA has always had (`t` or a space
/// for `T`, `UTC` or an offset for `Z`, spaces around the fields). Converted to UTC.
pub fn parse_rfc3339_relaxed(s: &str) -> Option<UtcTime> {
    imp::parse_rfc3339_relaxed(s)
}

/// Parse an ISO 8601 / RFC 3339 date string to a Unix timestamp (seconds).
///
/// Handles common formats from registry metadata:
/// - `2024-01-15T10:30:00Z` (Go .info `Time` field)
/// - `2024-01-15T10:30:00.123Z` (npm `time` field)
/// - `2024-01-15T10:30:00+00:00` (PyPI `upload_time_iso_8601`)
/// - `2024-01-15T10:30:00.000+0000` (Conan `time` field — non-standard tz offset)
/// - `2024-01-15T10:30:00` (no zone: UTC)
///
/// Returns `None` if the string is not parseable.
pub fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    imp::parse_iso8601_to_unix(s)
}

/// An RFC 2822 date (an upstream's `Last-Modified`) as seconds since the epoch.
pub fn parse_rfc2822_to_unix(s: &str) -> Option<i64> {
    imp::parse_rfc2822_to_unix(s)
}

/// The calendar and the grammars, on the `time` crate. The spellings are written out field by
/// field, and the parsers follow, rule for rule, the ones NORA 1.4.5 used (chrono 0.4.45): its
/// range of years, its leap seconds, the whitespace and signs it let through.
mod imp {
    use super::UtcTime;
    use time::{Date, Month, OffsetDateTime, Weekday};

    const NANOS: u32 = 1_000_000_000;
    const DAY: i64 = 86_400;
    /// -262143-01-01T00:00:00Z and 262142-12-31T23:59:59Z: the years NORA has always handled.
    const MIN_YEAR: i32 = -262_143;
    const MAX_YEAR: i32 = 262_142;
    const MIN_SECS: i64 = -8_334_601_228_800;
    const MAX_SECS: i64 = 8_210_266_876_799;

    pub(super) fn now() -> UtcTime {
        let now = OffsetDateTime::now_utc();
        UtcTime {
            secs: now.unix_timestamp(),
            nanos: now.nanosecond(),
        }
    }

    /// Nanoseconds reach into a second second only at `:59`, as a leap second.
    pub(super) fn checked(secs: i64, nanos: u32) -> Option<UtcTime> {
        let in_range = (MIN_SECS..=MAX_SECS).contains(&secs);
        let leap_ok = nanos < NANOS || (nanos < 2 * NANOS && secs.rem_euclid(60) == 59);
        (in_range && leap_ok).then_some(UtcTime { secs, nanos })
    }

    struct Fields {
        year: i32,
        month: Month,
        day: u8,
        weekday: Weekday,
        hour: u8,
        minute: u8,
        /// 60 in a leap second.
        second: u8,
        nanos: u32,
    }

    fn fields(t: UtcTime) -> Fields {
        let dt = OffsetDateTime::from_unix_timestamp(t.secs).expect("UtcTime is in the calendar");
        let (second, nanos) = if t.nanos >= NANOS {
            (dt.second() + 1, t.nanos - NANOS)
        } else {
            (dt.second(), t.nanos)
        };
        Fields {
            year: dt.year(),
            month: dt.month(),
            day: dt.day(),
            weekday: dt.weekday(),
            hour: dt.hour(),
            minute: dt.minute(),
            second,
            nanos,
        }
    }

    /// Four digits within 0..=9999; outside, signed (`-0001`, `+10000`), as ISO 8601 asks.
    fn year(y: i32) -> String {
        if (0..=9999).contains(&y) {
            format!("{y:04}")
        } else {
            format!("{y:+05}")
        }
    }

    /// No fraction for a whole second, else 3, 6 or 9 digits: as many groups as it needs.
    fn fraction(nanos: u32) -> String {
        if nanos == 0 {
            String::new()
        } else if nanos.is_multiple_of(1_000_000) {
            format!(".{:03}", nanos / 1_000_000)
        } else if nanos.is_multiple_of(1_000) {
            format!(".{:06}", nanos / 1_000)
        } else {
            format!(".{nanos:09}")
        }
    }

    fn weekday_name(w: Weekday) -> &'static str {
        match w {
            Weekday::Monday => "Mon",
            Weekday::Tuesday => "Tue",
            Weekday::Wednesday => "Wed",
            Weekday::Thursday => "Thu",
            Weekday::Friday => "Fri",
            Weekday::Saturday => "Sat",
            Weekday::Sunday => "Sun",
        }
    }

    fn month_name(m: Month) -> &'static str {
        match m {
            Month::January => "Jan",
            Month::February => "Feb",
            Month::March => "Mar",
            Month::April => "Apr",
            Month::May => "May",
            Month::June => "Jun",
            Month::July => "Jul",
            Month::August => "Aug",
            Month::September => "Sep",
            Month::October => "Oct",
            Month::November => "Nov",
            Month::December => "Dec",
        }
    }

    /// `YYYY-MM-DD`, `HH:MM:SS`.
    fn date_time(f: &Fields, separator: char) -> String {
        format!(
            "{}-{:02}-{:02}{separator}{:02}:{:02}:{:02}",
            year(f.year),
            f.month as u8,
            f.day,
            f.hour,
            f.minute,
            f.second
        )
    }

    pub(super) fn rfc3339(t: UtcTime, fraction_digits: bool) -> String {
        let f = fields(t);
        let fraction = if fraction_digits {
            fraction(f.nanos)
        } else {
            String::new()
        };
        format!("{}{fraction}Z", date_time(&f, 'T'))
    }

    /// `Tue, 17 Nov 2026 08:15:00 <zone>`.
    pub(super) fn imf_date(t: UtcTime, zone: &str) -> String {
        let f = fields(t);
        format!(
            "{}, {:02} {} {} {:02}:{:02}:{:02} {zone}",
            weekday_name(f.weekday),
            f.day,
            month_name(f.month),
            year(f.year),
            f.hour,
            f.minute,
            f.second
        )
    }

    pub(super) fn compact(t: UtcTime) -> String {
        let f = fields(t);
        format!(
            "{}{:02}{:02}{:02}{:02}{:02}",
            year(f.year),
            f.month as u8,
            f.day,
            f.hour,
            f.minute,
            f.second
        )
    }

    pub(super) fn composer(t: UtcTime) -> String {
        format!("{}+00:00", date_time(&fields(t), 'T'))
    }

    pub(super) fn display(t: UtcTime) -> String {
        let f = fields(t);
        format!("{}{} UTC", date_time(&f, ' '), fraction(f.nanos))
    }

    /// `later - earlier` in whole seconds toward zero. Within a day the times of day are
    /// compared, and a leap second counts as one when it lies between them.
    pub(super) fn seconds_between(earlier: UtcTime, later: UtcTime) -> i64 {
        let (days_a, sod_a) = (earlier.secs.div_euclid(DAY), earlier.secs.rem_euclid(DAY));
        let (days_b, sod_b) = (later.secs.div_euclid(DAY), later.secs.rem_euclid(DAY));
        let mut secs = sod_b - sod_a;
        if sod_b > sod_a && earlier.nanos >= NANOS {
            secs += 1;
        } else if sod_b < sod_a && later.nanos >= NANOS {
            secs -= 1;
        }
        let frac = i64::from(later.nanos) - i64::from(earlier.nanos);
        let whole = (days_b - days_a) * DAY + secs + frac.div_euclid(i64::from(NANOS));
        let rest = frac.rem_euclid(i64::from(NANOS));
        if whole < 0 && rest > 0 {
            whole + 1
        } else {
            whole
        }
    }

    // ---------------------------------------------------------------------------------------
    // Reading
    // ---------------------------------------------------------------------------------------

    /// The fields of a date and time as read, before the calendar has its say.
    #[derive(Default)]
    struct Read {
        year: i64,
        month: i64,
        day: i64,
        hour: i64,
        minute: i64,
        second: i64,
        nanos: u32,
        offset: i64,
        weekday: Option<Weekday>,
    }

    impl Read {
        /// The instant, if the fields name one: a real date in range, a time of day (second
        /// 60 being a leap second), an offset under a day, and the instant itself in range.
        fn instant(&self) -> Option<UtcTime> {
            let year = i32::try_from(self.year).ok()?;
            if !(MIN_YEAR..=MAX_YEAR).contains(&year)
                || !(1..=12).contains(&self.month)
                || !(1..=31).contains(&self.day)
                || !(0..=23).contains(&self.hour)
                || !(0..=59).contains(&self.minute)
                || !(0..=60).contains(&self.second)
                || self.offset.abs() >= DAY
            {
                return None;
            }
            let month = Month::try_from(self.month as u8).ok()?;
            let date = Date::from_calendar_date(year, month, self.day as u8).ok()?;
            if self.weekday.is_some_and(|w| w != date.weekday()) {
                return None;
            }
            let (second, nanos) = match self.second {
                60 => (59, self.nanos + NANOS),
                s => (s, self.nanos),
            };
            let midnight = date.midnight().assume_utc().unix_timestamp();
            let secs = midnight + self.hour * 3600 + self.minute * 60 + second - self.offset;
            checked(secs, nanos)
        }
    }

    /// Up to `max` ASCII digits, at least `min`.
    fn number(s: &str, min: usize, max: usize) -> Option<(&str, i64)> {
        let bytes = s.as_bytes();
        if bytes.len() < min {
            return None;
        }
        let mut n = 0i64;
        for (i, &c) in bytes.iter().take(max).enumerate() {
            if !c.is_ascii_digit() {
                return (i >= min).then(|| (&s[i..], n));
            }
            n = n.checked_mul(10)?.checked_add(i64::from(c - b'0'))?;
        }
        Some((&s[max.min(bytes.len())..], n))
    }

    /// The digits of a fraction: the first nine count, the rest are skipped.
    fn nanosecond(s: &str) -> Option<(&str, u32)> {
        const SCALE: [u32; 10] = [
            0,
            100_000_000,
            10_000_000,
            1_000_000,
            100_000,
            10_000,
            1_000,
            100,
            10,
            1,
        ];
        let (rest, v) = number(s, 1, 9)?;
        let consumed = s.len() - rest.len();
        let v = (v as u32).checked_mul(SCALE[consumed])?;
        Some((rest.trim_start_matches(|c: char| c.is_ascii_digit()), v))
    }

    /// A field written as a number: leading whitespace skipped; a year may carry a sign and
    /// then any number of digits, otherwise it has up to four.
    fn field(s: &str, width: usize, signed: bool) -> Option<(&str, i64)> {
        let s = s.trim_start();
        if signed {
            if let Some(rest) = s.strip_prefix('-') {
                let (rest, v) = number(rest, 1, usize::MAX)?;
                return Some((rest, 0i64.checked_sub(v)?));
            }
            if let Some(rest) = s.strip_prefix('+') {
                return number(rest, 1, usize::MAX);
            }
        }
        number(s, 1, width)
    }

    fn literal<'a>(s: &'a str, lit: &str) -> Option<&'a str> {
        s.strip_prefix(lit)
    }

    #[derive(Clone, Copy)]
    enum Colon {
        /// Exactly one `:`.
        One,
        /// Any run of `:` and whitespace, or none.
        Loose,
        /// None at all.
        Never,
    }

    /// `[+-−]HH[:]MM`, or `Z` where allowed, as seconds east of UTC.
    fn offset(s: &str, colon: Colon, zulu: bool, unicode_minus: bool) -> Option<(&str, i64)> {
        if zulu {
            if let Some(rest) = s.strip_prefix(['Z', 'z']) {
                return Some((rest, 0));
            }
        }
        let (s, negative) = if let Some(rest) = s.strip_prefix('+') {
            (rest, false)
        } else if let Some(rest) = s.strip_prefix('-') {
            (rest, true)
        } else if let Some(rest) = s.strip_prefix('\u{2212}').filter(|_| unicode_minus) {
            (rest, true)
        } else {
            return None;
        };
        let two = |s: &str| -> Option<(u8, u8)> {
            let b = s.as_bytes();
            (b.len() >= 2).then(|| (b[0], b[1]))
        };
        let hours = match two(s)? {
            (h1 @ b'0'..=b'9', h2 @ b'0'..=b'9') => i64::from((h1 - b'0') * 10 + (h2 - b'0')),
            _ => return None,
        };
        let s = &s[2..];
        let s = match colon {
            Colon::One => s.strip_prefix(':')?,
            Colon::Loose => s.trim_start_matches(|c: char| c == ':' || c.is_whitespace()),
            Colon::Never => s,
        };
        let minutes = match two(s)? {
            (m1 @ b'0'..=b'5', m2 @ b'0'..=b'9') => i64::from((m1 - b'0') * 10 + (m2 - b'0')),
            _ => return None,
        };
        let seconds = hours * 3600 + minutes * 60;
        Some((&s[2..], if negative { -seconds } else { seconds }))
    }

    /// RFC 3339 as written: `YYYY-MM-DD`, `T`/`t`/space, `HH:MM:SS`, an optional fraction, then
    /// `Z`/`z` or `±HH:MM`, nothing after.
    fn rfc3339_strict(s: &str) -> Option<UtcTime> {
        let b = s.as_bytes();
        if b.len() < 19 {
            return None;
        }
        let d = |i: usize| b[i].is_ascii_digit().then(|| i64::from(b[i] - b'0'));
        let two = |i: usize| Some(d(i)? * 10 + d(i + 1)?);
        let mut read = Read {
            year: d(0)? * 1000 + d(1)? * 100 + d(2)? * 10 + d(3)?,
            month: two(5)?,
            day: two(8)?,
            hour: two(11)?,
            minute: two(14)?,
            second: two(17)?,
            ..Read::default()
        };
        if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
            return None;
        }
        if b[13] != b':' || b[16] != b':' {
            return None;
        }
        let rest = if b.get(19) == Some(&b'.') {
            let (rest, nanos) = nanosecond(&s[20..])?;
            read.nanos = nanos;
            rest
        } else {
            &s[19..]
        };
        let (rest, offset) = offset(rest, Colon::One, true, true)?;
        read.offset = offset;
        rest.is_empty().then_some(())?;
        read.instant()
    }

    /// `%Y-%m-%dT%H:%M:%S`, then an optional `.fraction` and an optional `%z` offset; nothing
    /// left over. Without an offset the time is UTC.
    fn strftime_iso(s: &str, with_fraction: bool, with_offset: bool) -> Option<UtcTime> {
        let mut read = Read::default();
        let (s, v) = field(s, 4, true)?;
        read.year = v;
        let s = literal(s, "-")?;
        let (s, v) = field(s, 2, false)?;
        read.month = v;
        let s = literal(s, "-")?;
        let (s, v) = field(s, 2, false)?;
        read.day = v;
        let s = literal(s, "T")?;
        let (s, v) = field(s, 2, false)?;
        read.hour = v;
        let s = literal(s, ":")?;
        let (s, v) = field(s, 2, false)?;
        read.minute = v;
        let s = literal(s, ":")?;
        let (mut s, v) = field(s, 2, false)?;
        read.second = v;
        if with_fraction {
            if let Some(rest) = s.strip_prefix('.') {
                let (rest, nanos) = nanosecond(rest)?;
                read.nanos = nanos;
                s = rest;
            }
        }
        if with_offset {
            let (rest, offset) = offset(s.trim_start(), Colon::Loose, false, true)?;
            read.offset = offset;
            s = rest;
        }
        s.is_empty().then_some(())?;
        read.instant()
    }

    pub(super) fn parse_rfc3339_relaxed(s: &str) -> Option<UtcTime> {
        let mut read = Read::default();
        let (s, v) = field(s, 4, true)?;
        read.year = v;
        let s = literal(s.trim_start(), "-")?;
        let (s, v) = field(s, 2, false)?;
        read.month = v;
        let s = literal(s.trim_start(), "-")?;
        let (s, v) = field(s, 2, false)?;
        read.day = v;
        let s = s.strip_prefix(['t', 'T', ' '])?;
        let (s, v) = field(s, 2, false)?;
        read.hour = v;
        let s = literal(s.trim_start(), ":")?;
        let (s, v) = field(s, 2, false)?;
        read.minute = v;
        let s = literal(s.trim_start(), ":")?;
        let (mut s, v) = field(s, 2, false)?;
        read.second = v;
        if let Some(rest) = s.strip_prefix('.') {
            let (rest, nanos) = nanosecond(rest)?;
            read.nanos = nanos;
            s = rest;
        }
        let s = s.trim_start();
        let utc = s.len() >= 3 && s.as_bytes()[..3].eq_ignore_ascii_case(b"UTC");
        let (s, offset) = if utc {
            (&s[3..], 0)
        } else {
            offset(s, Colon::Loose, true, true)?
        };
        read.offset = offset;
        s.trim_start().is_empty().then_some(())?;
        read.instant()
    }

    pub(super) fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
        // RFC 3339 with a zone; then without one (UTC), as some registries write it; then
        // with an offset lacking its colon (`+0000`, `+0530`), as Conan Center does.
        rfc3339_strict(s)
            .or_else(|| strftime_iso(s, true, false))
            .or_else(|| strftime_iso(s, false, false))
            .or_else(|| strftime_iso(s, true, true))
            .or_else(|| strftime_iso(s, false, true))
            .map(UtcTime::unix)
    }

    /// Whitespace that must be there.
    fn space(s: &str) -> Option<&str> {
        let trimmed = s.trim_start();
        (trimmed.len() < s.len()).then_some(trimmed)
    }

    fn short_weekday(s: &str) -> Option<(&str, Weekday)> {
        let b = s.as_bytes();
        if b.len() < 3 {
            return None;
        }
        let w = match (b[0] | 32, b[1] | 32, b[2] | 32) {
            (b'm', b'o', b'n') => Weekday::Monday,
            (b't', b'u', b'e') => Weekday::Tuesday,
            (b'w', b'e', b'd') => Weekday::Wednesday,
            (b't', b'h', b'u') => Weekday::Thursday,
            (b'f', b'r', b'i') => Weekday::Friday,
            (b's', b'a', b't') => Weekday::Saturday,
            (b's', b'u', b'n') => Weekday::Sunday,
            _ => return None,
        };
        Some((&s[3..], w))
    }

    fn short_month(s: &str) -> Option<(&str, i64)> {
        let b = s.as_bytes();
        if b.len() < 3 {
            return None;
        }
        let m = match (b[0] | 32, b[1] | 32, b[2] | 32) {
            (b'j', b'a', b'n') => 1,
            (b'f', b'e', b'b') => 2,
            (b'm', b'a', b'r') => 3,
            (b'a', b'p', b'r') => 4,
            (b'm', b'a', b'y') => 5,
            (b'j', b'u', b'n') => 6,
            (b'j', b'u', b'l') => 7,
            (b'a', b'u', b'g') => 8,
            (b's', b'e', b'p') => 9,
            (b'o', b'c', b't') => 10,
            (b'n', b'o', b'v') => 11,
            (b'd', b'e', b'c') => 12,
            _ => return None,
        };
        Some((&s[3..], m))
    }

    /// An RFC 2822 zone: `GMT`/`UT`/`Z`, the US zones, a military letter (taken as UTC), or
    /// `±HHMM`.
    fn zone_2822(s: &str) -> Option<(&str, i64)> {
        let upto = s
            .as_bytes()
            .iter()
            .position(|c| !c.is_ascii_alphabetic())
            .unwrap_or(s.len());
        if upto == 0 {
            return offset(s, Colon::Never, false, false);
        }
        let name = s[..upto].to_ascii_lowercase();
        let rest = &s[upto..];
        let hours = match name.as_str() {
            "gmt" | "ut" | "z" => 0,
            "edt" => -4,
            "est" | "cdt" => -5,
            "cst" | "mdt" => -6,
            "mst" | "pdt" => -7,
            "pst" => -8,
            letter if letter.len() == 1 && letter != "j" => 0,
            _ => return None,
        };
        Some((rest, hours * 3600))
    }

    /// A parenthesized comment, nesting and `\` escapes allowed.
    fn comment_2822(s: &str) -> Option<&str> {
        let s = s.trim_start();
        let mut depth = 0usize;
        let mut escaped = false;
        for (i, c) in s.bytes().enumerate() {
            if depth == 0 {
                if c != b'(' {
                    return None;
                }
                depth = 1;
            } else if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'(' {
                depth += 1;
            } else if c == b')' {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[i + 1..]);
                }
            }
        }
        None
    }

    pub(super) fn parse_rfc2822_to_unix(s: &str) -> Option<i64> {
        let mut read = Read::default();
        let mut s = s.trim_start();
        if let Some((rest, weekday)) = short_weekday(s) {
            s = rest.strip_prefix(',')?;
            read.weekday = Some(weekday);
        }
        let (s, day) = number(s.trim_start(), 1, 2)?;
        read.day = day;
        let (s, month) = short_month(space(s)?)?;
        read.month = month;
        let s = space(s)?;
        let (rest, year) = number(s, 2, usize::MAX)?;
        read.year = match (s.len() - rest.len(), year) {
            (2, 0..=49) => year + 2000,
            (2, 50..=99) | (3, _) => year + 1900,
            _ => year,
        };
        let (s, hour) = number(space(rest)?, 2, 2)?;
        read.hour = hour;
        let s = s.trim_start().strip_prefix(':')?.trim_start();
        let (mut s, minute) = number(s, 2, 2)?;
        read.minute = minute;
        if let Some(rest) = s.trim_start().strip_prefix(':') {
            let (rest, second) = number(rest, 2, 2)?;
            read.second = second;
            s = rest;
        }
        let (mut s, offset) = zone_2822(space(s)?)?;
        read.offset = offset;
        while let Some(rest) = comment_2822(s) {
            s = rest;
        }
        s.is_empty().then_some(())?;
        read.instant().map(UtcTime::unix)
    }
}

#[cfg(test)]
#[path = "datetime_golden.rs"]
mod golden;
