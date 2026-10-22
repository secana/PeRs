//! Checked little endian access to the bytes of a PE file and the string decoding rules of PeNet.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::error::{Error, Result};

/// A view on the bytes of a PE file. All reads are bounds checked.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bytes<'a>(pub &'a [u8]);

impl<'a> Bytes<'a> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn slice(&self, offset: usize, length: usize) -> Result<&'a [u8]> {
        offset
            .checked_add(length)
            .and_then(|end| self.0.get(offset..end))
            .ok_or(Error::OutOfBounds {
                offset: offset as u64,
                length: length as u64,
                data_length: self.0.len() as u64,
            })
    }

    /// All bytes from `offset` to the end. `offset` may equal the length.
    pub fn tail(&self, offset: usize) -> Result<&'a [u8]> {
        self.slice(offset, self.0.len().saturating_sub(offset))
    }

    pub fn array<const N: usize>(&self, offset: usize) -> Result<[u8; N]> {
        Ok(self
            .slice(offset, N)?
            .try_into()
            .expect("slice has N bytes"))
    }

    pub fn u8(&self, offset: usize) -> Result<u8> {
        Ok(self.array::<1>(offset)?[0])
    }

    pub fn u16(&self, offset: usize) -> Result<u16> {
        self.array(offset).map(u16::from_le_bytes)
    }

    pub fn u32(&self, offset: usize) -> Result<u32> {
        self.array(offset).map(u32::from_le_bytes)
    }

    pub fn u64(&self, offset: usize) -> Result<u64> {
        self.array(offset).map(u64::from_le_bytes)
    }

    /// A pointer sized value: 8 bytes for 64 bit files, 4 bytes otherwise.
    pub fn pointer(&self, offset: usize, is_64_bit: bool) -> Result<u64> {
        if is_64_bit {
            self.u64(offset)
        } else {
            self.u32(offset).map(u64::from)
        }
    }

    /// A reference to a fixed layout structure.
    pub fn read<T: FromBytes + KnownLayout + Immutable + Unaligned>(
        &self,
        offset: usize,
    ) -> Result<&'a T> {
        let bytes = self.slice(offset, size_of::<T>())?;
        Ok(T::ref_from_bytes(bytes).expect("unaligned structure of the right size"))
    }

    /// A slice of `count` fixed layout structures.
    pub fn read_slice<T: FromBytes + Immutable + Unaligned>(
        &self,
        offset: usize,
        count: usize,
    ) -> Result<&'a [T]> {
        let length = count
            .checked_mul(size_of::<T>())
            .ok_or(Error::OutOfBounds {
                offset: offset as u64,
                length: u64::MAX,
                data_length: self.0.len() as u64,
            })?;
        let bytes = self.slice(offset, length)?;
        Ok(<[T]>::ref_from_bytes(bytes).expect("unaligned structures of the right size"))
    }

    /// The bytes of a zero terminated string, without the terminator.
    pub fn c_string(&self, offset: usize) -> Result<&'a [u8]> {
        let tail = self.tail(offset)?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::UnterminatedString {
                offset: offset as u64,
            })?;
        Ok(&tail[..end])
    }

    /// A zero terminated ASCII string. Bytes above 0x7F are decoded as `?`.
    pub fn ascii_string(&self, offset: usize) -> Result<Cow<'a, str>> {
        Ok(decode_ascii(self.c_string(offset)?))
    }

    #[cfg(feature = "resources")]
    /// A UTF-16LE string ending at the first `00 00` byte pair after `offset`, regardless of its
    /// alignment. Without such a pair the result is empty.
    pub fn utf16_string(&self, offset: usize) -> Result<String> {
        let tail = self.tail(offset)?;
        Ok(match tail.windows(2).position(|w| w == [0, 0]) {
            Some(index) => decode_utf16le(&tail[..index + 1]),
            None => String::new(),
        })
    }

    /// `length` UTF-16LE code units.
    pub fn utf16_string_with_length(&self, offset: usize, length: usize) -> Result<String> {
        Ok(decode_utf16le(
            self.slice(offset, length.saturating_mul(2))?,
        ))
    }
}

/// Decode like `Encoding.ASCII.GetString`: every byte above 0x7F becomes `?`. Borrows the input if
/// it is pure ASCII.
pub(crate) fn decode_ascii(bytes: &[u8]) -> Cow<'_, str> {
    if bytes.is_ascii() {
        Cow::Borrowed(core::str::from_utf8(bytes).expect("ASCII is valid UTF-8"))
    } else {
        Cow::Owned(
            bytes
                .iter()
                .map(|&b| if b.is_ascii() { b as char } else { '?' })
                .collect(),
        )
    }
}

/// Decode like `Encoding.Unicode.GetString`: lone surrogates and an odd trailing byte become
/// U+FFFD.
pub(crate) fn decode_utf16le(bytes: &[u8]) -> String {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c));
    let mut s: String = char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if bytes.len() % 2 == 1 {
        s.push(char::REPLACEMENT_CHARACTER);
    }
    s
}

/// Encode like `Encoding.ASCII.GetBytes`: every non ASCII character becomes `?`.
pub(crate) fn encode_ascii(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
        .collect()
}

/// Number of UTF-16 code units of a string, which is the .NET `string.Length`.
#[cfg(feature = "resources")]
pub(crate) fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ascii_replaces_non_ascii_bytes() {
        assert_eq!("a?b", decode_ascii(&[b'a', 0xe4, b'b']));
    }

    #[test]
    fn decode_ascii_borrows_ascii_input() {
        assert!(matches!(decode_ascii(b"abc"), Cow::Borrowed("abc")));
    }

    #[test]
    fn decode_utf16le_replaces_odd_trailing_byte() {
        assert_eq!("h\u{fffd}", decode_utf16le(&[0x68, 0x00, 0x65]));
    }

    #[cfg(feature = "resources")]
    #[test]
    fn utf16_string_ends_at_first_zero_pair() {
        let bytes = Bytes(&[0x00, 0x00, 0x68, 0x00, 0x69, 0x00, 0x00, 0x00, 0x11]);
        assert_eq!("hi", bytes.utf16_string(2).unwrap());
    }

    #[test]
    fn c_string_without_terminator_is_an_error() {
        assert!(matches!(
            Bytes(b"abc").c_string(0),
            Err(Error::UnterminatedString { offset: 0 })
        ));
    }
}
