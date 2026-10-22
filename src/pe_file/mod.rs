//! The [`PeFile`] facade, the entry point of the library.

#[cfg(feature = "authenticode")]
mod authenticode;
mod data_directories;
#[cfg(feature = "dotnet")]
mod dot_net;
#[cfg(feature = "resources")]
mod resources;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::pe::{FileCharacteristics, ImageDosHeader, MagicType, NtHeaders, SectionTable};

/// A parsed Portable Executable file borrowing its data.
///
/// The DOS and NT headers are parsed by [`PeFile::parse`], everything else on access. Accessors
/// of optional structures return `Ok(None)` if the structure is absent and an error if it is
/// malformed.
#[derive(Debug)]
pub struct PeFile<'a> {
    data: &'a [u8],
    dos_header: &'a ImageDosHeader,
    nt_headers: NtHeaders<'a>,
    section_headers: Result<SectionTable<'a>>,
    #[cfg_attr(
        not(any(feature = "dotnet", feature = "authenticode")),
        allow(dead_code)
    )]
    cache: Cache<'a>,
}

/// Cached results of expensive parsers.
#[derive(Debug, Default)]
struct Cache<'a> {
    #[cfg(feature = "dotnet")]
    dot_net: dot_net::DotNetCache<'a>,
    #[cfg(feature = "authenticode")]
    authenticode: crate::lazy::Lazy<Result<Option<crate::authenticode::AuthenticodeInfo<'a>>>>,
    _data: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> PeFile<'a> {
    /// Parse a PE file. Fails with [`Error::NotAPeFile`] if the NT signature is not `PE\0\0`.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let dos_header = ImageDosHeader::parse(data, 0)
            .map_err(|_| Error::NotAPeFile("too small for a DOS header"))?;
        let nt_headers = NtHeaders::parse(data, dos_header.e_lfanew() as usize)
            .map_err(|_| Error::NotAPeFile("NT headers outside of the file"))?;
        if nt_headers.signature != NtHeaders::SIGNATURE {
            return Err(Error::NotAPeFile("missing PE signature"));
        }
        let section_headers = SectionTable::parse(
            data,
            nt_headers.section_table_offset(),
            nt_headers.file_header.number_of_sections(),
            nt_headers.optional_header.image_base(),
        );
        Ok(Self {
            data,
            dos_header,
            nt_headers,
            section_headers,
            cache: Cache::default(),
        })
    }

    /// True if the data starts with the `MZ` magic. The rest of the data is not checked.
    pub fn is_pe(data: &[u8]) -> bool {
        data.starts_with(b"MZ")
    }

    /// True if the reader starts with the `MZ` magic. The rest of the data is not checked.
    #[cfg(feature = "std")]
    pub fn is_pe_reader(reader: &mut impl std::io::Read) -> Result<bool> {
        let mut magic = [0u8; 2];
        reader.read_exact(&mut magic)?;
        Ok(Self::is_pe(&magic))
    }

    /// The file data.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn dos_header(&self) -> &'a ImageDosHeader {
        self.dos_header
    }

    pub fn nt_headers(&self) -> &NtHeaders<'a> {
        &self.nt_headers
    }

    /// The section headers sorted by virtual address.
    pub fn section_headers(&self) -> Result<&SectionTable<'a>> {
        self.section_headers.as_ref().map_err(Clone::clone)
    }

    /// True if the optional header has the 64 bit magic.
    pub fn is_64_bit(&self) -> bool {
        self.nt_headers.optional_header.magic() == MagicType::Bit64
    }

    /// True if the optional header has the 32 bit magic.
    pub fn is_32_bit(&self) -> bool {
        self.nt_headers.optional_header.magic() == MagicType::Bit32
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics().contains(FileCharacteristics::DLL)
    }

    pub fn is_exe(&self) -> bool {
        self.characteristics()
            .contains(FileCharacteristics::EXECUTABLE_IMAGE)
    }

    fn characteristics(&self) -> FileCharacteristics {
        self.nt_headers.file_header.characteristics()
    }

    pub fn md5(&self) -> [u8; 16] {
        Md5::digest(self.data).into()
    }

    pub fn sha1(&self) -> [u8; 20] {
        Sha1::digest(self.data).into()
    }

    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.data).into()
    }
}

impl<'a> TryFrom<&'a [u8]> for PeFile<'a> {
    type Error = Error;

    fn try_from(data: &'a [u8]) -> Result<Self> {
        Self::parse(data)
    }
}
