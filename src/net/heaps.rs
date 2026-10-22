//! The metadata heaps `#Strings`, `#US`, `#GUID` and `#Blob`. Heaps borrow their bytes from the
//! file; a heap that exceeds the file is cut off at the end of the file.

use alloc::borrow::Cow;
use alloc::string::String;

use uuid::Uuid;

use super::file_offset;
use crate::address::FileOffset;
use crate::bytes::{Bytes, decode_ascii, decode_utf16le};
use crate::error::{Error, Result};

macro_rules! heap {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name<'a> {
            offset: FileOffset,
            data: &'a [u8],
        }

        impl<'a> $name<'a> {
            /// The heap at `offset` with `size` bytes, cut off at the end of `data`.
            pub fn parse(data: &'a [u8], offset: usize, size: usize) -> Result<Self> {
                let tail = Bytes(data).tail(offset)?;
                Ok(Self {
                    offset: file_offset(offset, "metadata heap")?,
                    data: &tail[..size.min(tail.len())],
                })
            }

            pub fn offset(&self) -> FileOffset {
                self.offset
            }

            /// The bytes of the heap.
            pub fn data(&self) -> &'a [u8] {
                self.data
            }
        }
    };
}

heap!(
    /// The `#Strings` heap with the zero terminated identifiers of the assembly.
    StringsHeap
);

heap!(
    /// The `#US` heap with the user strings (string literals) of the assembly.
    UserStringsHeap
);

heap!(
    /// The `#GUID` heap. GUIDs are referenced by their 1 based index.
    GuidHeap
);

heap!(
    /// The `#Blob` heap with length prefixed binary values.
    BlobHeap
);

impl<'a> StringsHeap<'a> {
    /// The zero terminated string at `index`, a byte offset into the heap. Bytes above 0x7F are
    /// decoded as `?`.
    pub fn get(&self, index: u32) -> Result<Cow<'a, str>> {
        let unterminated = || Error::UnterminatedString {
            offset: u64::from(self.offset.get()) + u64::from(index),
        };
        let tail = self.data.get(index as usize..).ok_or_else(unterminated)?;
        let length = tail.iter().position(|&b| b == 0).ok_or_else(unterminated)?;
        Ok(decode_ascii(&tail[..length]))
    }
}

/// A string of the `#US` heap.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UserString {
    /// Byte offset of the entry in the heap, the index used by `ldstr` tokens.
    pub index: u32,
    pub value: String,
}

impl<'a> UserStringsHeap<'a> {
    /// The user string at `index`, a byte offset into the heap.
    pub fn get(&self, index: u32) -> Result<String> {
        let (value, _) = self.entry(index as usize)?;
        Ok(value)
    }

    /// All user strings after the empty string at index 0. The walk ends at the first entry of
    /// length 0, which is the padding at the end of the heap.
    pub fn iter(&self) -> UserStrings<'a> {
        UserStrings {
            heap: *self,
            position: 1,
        }
    }

    /// The string and the length of the entry at `position`.
    fn entry(&self, position: usize) -> Result<(String, usize)> {
        let (length, header) = compressed_length(self.data, position)?;
        let start = position + header;
        let bytes = Bytes(self.data).slice(start, length)?;
        // The last byte flags strings with characters that need special handling.
        let text = bytes
            .get(..length.saturating_sub(1) & !1)
            .unwrap_or_default();
        Ok((decode_utf16le(text), header + length))
    }
}

/// Iterator over the strings of a [`UserStringsHeap`]. It ends after the first error.
#[derive(Debug, Clone)]
pub struct UserStrings<'a> {
    heap: UserStringsHeap<'a>,
    position: usize,
}

impl Iterator for UserStrings<'_> {
    type Item = Result<UserString>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.heap.data.get(self.position).is_none_or(|&b| b == 0) {
            return None;
        }
        let index = self.position as u32;
        match self.heap.entry(self.position) {
            Ok((value, length)) => {
                self.position += length;
                Some(Ok(UserString { index, value }))
            }
            Err(error) => {
                self.position = self.heap.data.len();
                Some(Err(error))
            }
        }
    }
}

const GUID_SIZE: usize = 16;

impl GuidHeap<'_> {
    /// The GUID at the 1 based `index`, `None` for 0 and indices behind the heap.
    pub fn get(&self, index: u32) -> Option<Uuid> {
        let index = (index as usize).checked_sub(1)?;
        self.guids()
            .get(index)
            .map(|bytes| Uuid::from_bytes_le(*bytes))
    }

    pub fn iter(&self) -> impl Iterator<Item = Uuid> + '_ {
        self.guids().iter().map(|bytes| Uuid::from_bytes_le(*bytes))
    }

    /// Number of GUIDs. Trailing bytes that do not form a complete GUID are ignored.
    pub fn len(&self) -> usize {
        self.guids().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn guids(&self) -> &[[u8; GUID_SIZE]] {
        self.data.as_chunks().0
    }
}

impl<'a> BlobHeap<'a> {
    /// The value at `index`, a byte offset into the heap, without its length prefix.
    pub fn get(&self, index: u32) -> Result<&'a [u8]> {
        let (length, header) = compressed_length(self.data, index as usize)?;
        Bytes(self.data).slice(index as usize + header, length)
    }
}

/// Decode an ECMA-335 compressed unsigned integer: the length and the size of its encoding.
fn compressed_length(data: &[u8], offset: usize) -> Result<(usize, usize)> {
    let bytes = Bytes(data);
    let first = bytes.u8(offset)?;
    Ok(match first {
        0x00..=0x7F => (usize::from(first), 1),
        0x80..=0xBF => (
            usize::from(u16::from_be_bytes(bytes.array(offset)?) & 0x3FFF),
            2,
        ),
        _ => (
            (u32::from_be_bytes(bytes.array(offset)?) & 0x1FFF_FFFF) as usize,
            4,
        ),
    })
}
