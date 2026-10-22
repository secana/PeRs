use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::file_offset;
use crate::address::FileOffset;
use crate::bytes::{Bytes, decode_ascii};
use crate::error::Result;

/// Offset of the version string in the metadata root.
const VERSION_OFFSET: usize = 0x10;
/// Size of the offset and size fields of a stream header.
const STREAM_HEADER_FIELDS: usize = 8;

/// The metadata root of a .NET assembly, referenced by the CLI header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MetadataHeader<'a> {
    pub offset: FileOffset,
    /// Always 0x424A5342 (`BSJB`) in a valid assembly.
    pub signature: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub reserved: u32,
    /// Length of the version string rounded up to a multiple of 4.
    pub version_length: u32,
    /// The version string, up to the first zero byte within `version_length`.
    pub version: Cow<'a, str>,
    pub flags: u16,
    /// Number of stream headers.
    pub streams: u16,
    pub stream_headers: Vec<StreamHeader<'a>>,
}

impl<'a> MetadataHeader<'a> {
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let version_length = bytes.u32(offset + 0xC)?;
        let version_start = offset + VERSION_OFFSET;
        let version = bytes.slice(version_start, version_length as usize)?;
        let version = version.split(|&b| b == 0).next().unwrap_or_default();
        let flags_offset = version_start + version_length as usize;
        let streams = bytes.u16(flags_offset + 2)?;
        Ok(Self {
            offset: file_offset(offset, "metadata header")?,
            signature: bytes.u32(offset)?,
            major_version: bytes.u16(offset + 4)?,
            minor_version: bytes.u16(offset + 6)?,
            reserved: bytes.u32(offset + 8)?,
            version_length,
            version: decode_ascii(version),
            flags: bytes.u16(flags_offset)?,
            streams,
            stream_headers: parse_stream_headers(data, flags_offset + 4, streams)?,
        })
    }

    /// The first stream header with the given name, e.g. `#Strings`.
    pub fn stream(&self, name: &str) -> Option<&StreamHeader<'a>> {
        self.stream_headers.iter().find(|s| s.name == name)
    }
}

fn parse_stream_headers(data: &[u8], offset: usize, count: u16) -> Result<Vec<StreamHeader<'_>>> {
    let mut headers = Vec::new();
    let mut current = offset;
    for _ in 0..count {
        let header = StreamHeader::parse(data, current)?;
        current += header.header_length as usize;
        headers.push(header);
    }
    Ok(headers)
}

/// The header of a metadata stream such as `#~`, `#Strings`, `#US`, `#GUID` or `#Blob`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamHeader<'a> {
    pub offset: FileOffset,
    /// Offset of the stream relative to the metadata root.
    pub stream_offset: u32,
    pub size: u32,
    pub name: Cow<'a, str>,
    /// Length of the header including the name and its padding to 4 bytes.
    pub header_length: u32,
}

impl<'a> StreamHeader<'a> {
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let name = bytes.c_string(offset + STREAM_HEADER_FIELDS)?;
        let padded_name = (name.len() + 4) & !3;
        Ok(Self {
            offset: file_offset(offset, "metadata header")?,
            stream_offset: bytes.u32(offset)?,
            size: bytes.u32(offset + 4)?,
            name: decode_ascii(name),
            header_length: (STREAM_HEADER_FIELDS + padded_name) as u32,
        })
    }
}
