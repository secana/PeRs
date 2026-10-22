//! Decoding of ASN.1 UTCTime and GeneralizedTime values, including the fractional seconds that
//! RFC 3161 time stamps may use.

use super::asn1::{TAG_GENERALIZED_TIME, TAG_UTC_TIME, Tlv};
use crate::error::{Error, Result, malformed};

/// A point in time (UTC) as seconds and nanoseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    pub unix_seconds: i64,
    pub nanos: u32,
}

impl Timestamp {
    /// The time as `SystemTime`, `None` before the Unix epoch.
    #[cfg(feature = "std")]
    pub fn to_system_time(self) -> Option<std::time::SystemTime> {
        let seconds = u64::try_from(self.unix_seconds).ok()?;
        Some(std::time::UNIX_EPOCH + core::time::Duration::new(seconds, self.nanos))
    }
}

/// Decode a UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSS[.f*]Z`).
pub(crate) fn decode_time(tlv: &Tlv) -> Result<Timestamp> {
    let text = core::str::from_utf8(tlv.value).map_err(|_| invalid_time())?;
    let text = text.strip_suffix('Z').ok_or_else(invalid_time)?;
    let (year, rest) = match tlv.tag {
        TAG_UTC_TIME => {
            let yy = number(text.get(..2))?;
            (
                if yy < 50 { 2000 + yy } else { 1900 + yy },
                text.get(2..).unwrap_or_default(),
            )
        }
        TAG_GENERALIZED_TIME => (number(text.get(..4))?, text.get(4..).unwrap_or_default()),
        _ => return Err(invalid_time()),
    };
    let (whole, fraction) = rest.split_once('.').unwrap_or((rest, ""));
    if whole.len() != 10 {
        return Err(invalid_time());
    }
    let field = |i: usize| number(whole.get(i..i + 2));
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(invalid_time());
    }
    Ok(Timestamp {
        unix_seconds: days_from_civil(year as i64, month, day) * 86_400
            + (hour * 3600 + minute * 60 + second) as i64,
        nanos: nanos(fraction)?,
    })
}

/// Nanoseconds of the digits after the decimal point. Digits beyond nanoseconds are ignored.
fn nanos(fraction: &str) -> Result<u32> {
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid_time());
    }
    Ok(fraction
        .bytes()
        .chain(core::iter::repeat(b'0'))
        .take(9)
        .fold(0, |acc, digit| acc * 10 + (digit - b'0') as u32))
}

fn number(digits: Option<&str>) -> Result<u32> {
    digits
        .filter(|d| d.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|d| d.parse().ok())
        .ok_or_else(invalid_time)
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn invalid_time() -> Error {
    malformed("ASN.1 time", "invalid format")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Tlv<'_> {
        Tlv {
            tag,
            value,
            raw: value,
        }
    }

    #[test]
    fn decode_generalized_time_with_fraction() {
        let time = decode_time(&tlv(TAG_GENERALIZED_TIME, b"20170101120000.5Z")).unwrap();
        assert_eq!(
            Timestamp {
                unix_seconds: 1_483_272_000,
                nanos: 500_000_000
            },
            time
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn to_system_time_converts_after_epoch_and_rejects_before() {
        let after = Timestamp {
            unix_seconds: 951_782_400,
            nanos: 5,
        };
        let before = Timestamp {
            unix_seconds: -1,
            nanos: 0,
        };

        assert_eq!(
            std::time::UNIX_EPOCH + core::time::Duration::new(951_782_400, 5),
            after.to_system_time().unwrap()
        );
        assert_eq!(None, before.to_system_time());
    }

    #[test]
    fn decode_utc_time() {
        let time = decode_time(&tlv(TAG_UTC_TIME, b"000229000000Z")).unwrap();
        assert_eq!(
            Timestamp {
                unix_seconds: 951_782_400,
                nanos: 0
            },
            time
        );
    }
}
