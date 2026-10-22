use alloc::borrow::Cow;

use uuid::Uuid;
use zerocopy::little_endian::{U16, U32};

use crate::address::{FileOffset, Rva};
use crate::bytes::Bytes;
use crate::error::Result;

pe_struct! {
    /// An IMAGE_DEBUG_DIRECTORY entry.
    pub struct ImageDebugDirectory {
        characteristics: U32 => u32,
        time_date_stamp: U32 => u32,
        major_version: U16 => u16,
        minor_version: U16 => u16,
        debug_type: U32 => DebugDirectoryType,
        size_of_data: U32 => u32,
        address_of_raw_data: U32 => Rva,
        pointer_to_raw_data: U32 => FileOffset,
    }
}

impl ImageDebugDirectory {
    /// The PDB information of a CodeView entry, `Ok(None)` for other entries.
    pub fn cv_info_pdb70<'a>(&self, data: &'a [u8]) -> Result<Option<CvInfoPdb70<'a>>> {
        if self.debug_type() != DebugDirectoryType::CodeView {
            return Ok(None);
        }
        CvInfoPdb70::parse(data, self.pointer_to_raw_data().usize()).map(Some)
    }

    /// The flags of an extended DLL characteristics entry, `Ok(None)` for other entries.
    pub fn extended_dll_characteristics(
        &self,
        data: &[u8],
    ) -> Result<Option<ExtendedDllCharacteristics>> {
        if self.debug_type() != DebugDirectoryType::ExtendedDllCharacteristics {
            return Ok(None);
        }
        let bits = Bytes(data).u32(self.pointer_to_raw_data().usize())?;
        Ok(Some(ExtendedDllCharacteristics::from_bits_retain(bits)))
    }
}

/// The CodeView PDB 7.0 information (`RSDS` signature).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CvInfoPdb70<'a> {
    pub cv_signature: u32,
    /// The PDB GUID, decoded like a .NET `Guid`.
    pub signature: Uuid,
    pub age: u32,
    pub pdb_file_name: Cow<'a, str>,
}

impl<'a> CvInfoPdb70<'a> {
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        Ok(Self {
            cv_signature: bytes.u32(offset)?,
            signature: Uuid::from_bytes_le(bytes.array(offset + 4)?),
            age: bytes.u32(offset + 0x14)?,
            pdb_file_name: bytes.ascii_string(offset + 0x18)?,
        })
    }
}

pe_enum! {
    pub enum DebugDirectoryType: u32 {
        Unknown = 0,
        Coff = 1,
        CodeView = 2,
        FramePointerOmission = 3,
        Misc = 4,
        Exception = 5,
        Fixup = 6,
        OMapToSource = 7,
        OMapFromSource = 8,
        Borland = 9,
        Reserved10 = 10,
        Clsid = 11,
        VcFeature = 12,
        Pogo = 13,
        Iltcg = 14,
        Mpx = 15,
        Reproducible = 16,
        EmbeddedPortablePdb = 17,
        Reserved18 = 18,
        PdbChecksum = 19,
        ExtendedDllCharacteristics = 20,
    }
}

bitflags::bitflags! {
    /// Flags of the extended DLL characteristics debug entry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ExtendedDllCharacteristics: u32 {
        const CET_COMPAT = 0x01;
        const CET_COMPAT_STRICT_MODE = 0x02;
        const CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE = 0x04;
        const CET_DYNAMIC_APIS_ALLOW_IN_PROC = 0x08;
        const CET_RESERVED1 = 0x10;
        const CET_RESERVED2 = 0x20;
    }
}
