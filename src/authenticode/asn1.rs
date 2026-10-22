//! A minimal DER reader that keeps the raw bytes of every element. Authenticode verification
//! needs the exact encoded bytes (e.g. of the signed attributes), which a decoder into owned types
//! would re-encode. Only definite lengths and single byte tags are supported.

use alloc::vec::Vec;

use crate::error::{Error, Result};

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTC_TIME: u8 = 0x17;
pub const TAG_GENERALIZED_TIME: u8 = 0x18;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;
pub const TAG_CONTEXT_0: u8 = 0xA0;
pub const TAG_CONTEXT_1: u8 = 0xA1;

/// One encoded element: tag, value and the complete encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    /// Tag, length and value.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Read the first element of `data`. Trailing bytes are ignored.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        read_tlv(data).map(|(tlv, _)| tlv)
    }

    /// Read the first element and check its tag.
    pub fn parse_tagged(data: &'a [u8], tag: u8) -> Result<Self> {
        Self::parse(data)?.expect_tag(tag)
    }

    pub fn expect_tag(self, tag: u8) -> Result<Self> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(malformed("unexpected tag"))
        }
    }

    /// The elements inside a constructed element.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>> {
        let mut children = Vec::new();
        let mut rest = self.value;
        while !rest.is_empty() {
            let (child, remaining) = read_tlv(rest)?;
            children.push(child);
            rest = remaining;
        }
        Ok(children)
    }

    /// The `index`-th child, which must have the given tag.
    pub fn child(&self, index: usize, tag: u8) -> Result<Tlv<'a>> {
        self.children()?
            .get(index)
            .copied()
            .ok_or_else(|| malformed("missing element"))?
            .expect_tag(tag)
    }
}

/// Read one element and return it with the remaining bytes.
pub fn read_tlv(data: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = data.split_first().ok_or_else(|| malformed("empty input"))?;
    if tag & 0x1F == 0x1F {
        return Err(malformed("multi byte tags are not supported"));
    }
    let (&first, rest) = rest
        .split_first()
        .ok_or_else(|| malformed("missing length"))?;
    let (length, rest) = if first & 0x80 == 0 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 8 || rest.len() < count {
            return Err(malformed("unsupported length encoding"));
        }
        let length = rest[..count]
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | b as u64);
        (
            usize::try_from(length).map_err(|_| malformed("length overflow"))?,
            &rest[count..],
        )
    };
    if rest.len() < length {
        return Err(malformed("element exceeds the input"));
    }
    let header_length = data.len() - rest.len();
    let tlv = Tlv {
        tag,
        value: &rest[..length],
        raw: &data[..header_length + length],
    };
    Ok((tlv, &rest[length..]))
}

fn malformed(reason: &'static str) -> Error {
    crate::error::malformed("ASN.1 element", reason)
}
