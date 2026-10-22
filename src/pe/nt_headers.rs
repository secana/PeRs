use super::{DataDirectoryType, ImageDataDirectory, ImageFileHeader, OptionalHeader};
use crate::bytes::Bytes;
use crate::error::Result;

/// The IMAGE_NT_HEADERS: signature, file header, optional header and data directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NtHeaders<'a> {
    pub offset: usize,
    /// `PE\0\0` (0x4550) for a valid PE file.
    pub signature: u32,
    pub file_header: &'a ImageFileHeader,
    pub optional_header: OptionalHeader<'a>,
    /// Always 16 entries, independent of `number_of_rva_and_sizes`.
    pub data_directories: &'a [ImageDataDirectory],
}

impl<'a> NtHeaders<'a> {
    pub const SIGNATURE: u32 = 0x4550;

    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let optional_header_offset = offset + 0x18;
        let optional_header = OptionalHeader::parse(data, optional_header_offset)?;
        let data_directories =
            ImageDataDirectory::parse_table(data, optional_header_offset + optional_header.size())?;
        Ok(Self {
            offset,
            signature: bytes.u32(offset)?,
            file_header: bytes.read(offset + 0x4)?,
            optional_header,
            data_directories,
        })
    }

    pub fn data_directory(&self, t: DataDirectoryType) -> &'a ImageDataDirectory {
        &self.data_directories[t as usize]
    }

    /// File offset of a data directory entry.
    pub(crate) fn data_directory_offset(&self, t: DataDirectoryType) -> usize {
        self.optional_header_offset()
            + self.optional_header.size()
            + t as usize * ImageDataDirectory::SIZE
    }

    pub(crate) fn optional_header_offset(&self) -> usize {
        self.offset + 0x18
    }

    /// File offset of the section table, directly after the optional header.
    pub(crate) fn section_table_offset(&self) -> usize {
        self.optional_header_offset() + self.file_header.size_of_optional_header() as usize
    }
}
