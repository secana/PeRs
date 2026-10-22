use zerocopy::little_endian::{U16, U32};

use crate::address::Rva;
use crate::bytes::Bytes;
use crate::error::Result;

pe_layouts! {
    for OptionalHeader<'_>;
    /// The IMAGE_OPTIONAL_HEADER32 without the data directories.
    pub struct ImageOptionalHeader32;
    /// The IMAGE_OPTIONAL_HEADER64 without the data directories.
    pub struct ImageOptionalHeader64;
    fields {
            fixed magic: U16 => MagicType,
            fixed major_linker_version: u8 => u8,
            fixed minor_linker_version: u8 => u8,
            fixed size_of_code: U32 => u32,
            fixed size_of_initialized_data: U32 => u32,
            fixed size_of_uninitialized_data: U32 => u32,
            fixed address_of_entry_point: U32 => Rva,
            fixed base_of_code: U32 => Rva,
            pe32 base_of_data: U32 => Rva,
            ptr image_base,
            fixed section_alignment: U32 => u32,
            fixed file_alignment: U32 => u32,
            fixed major_operating_system_version: U16 => u16,
            fixed minor_operating_system_version: U16 => u16,
            fixed major_image_version: U16 => u16,
            fixed minor_image_version: U16 => u16,
            fixed major_subsystem_version: U16 => u16,
            fixed minor_subsystem_version: U16 => u16,
            fixed win32_version_value: U32 => u32,
            fixed size_of_image: U32 => u32,
            fixed size_of_headers: U32 => u32,
            fixed check_sum: U32 => u32,
            fixed subsystem: U16 => SubsystemType,
            fixed dll_characteristics: U16 => DllCharacteristics,
            ptr size_of_stack_reserve,
            ptr size_of_stack_commit,
            ptr size_of_heap_reserve,
            ptr size_of_heap_commit,
            fixed loader_flags: U32 => u32,
            fixed number_of_rva_and_sizes: U32 => u32,
    }
}

/// The optional header of a 32 or 64 bit file. Pointer sized values are widened to `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionalHeader<'a> {
    Pe32(&'a ImageOptionalHeader32),
    Pe64(&'a ImageOptionalHeader64),
}

impl<'a> OptionalHeader<'a> {
    /// Parse the header at `offset`. A magic of `0x20b` selects the 64 bit layout, every other
    /// value the 32 bit layout.
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let is_64_bit = Bytes(data).u16(offset)? == MagicType::Bit64.value();
        Self::parse_as(data, offset, is_64_bit)
    }

    /// Parse the header with the given layout, independent of the magic.
    pub fn parse_as(data: &'a [u8], offset: usize, is_64_bit: bool) -> Result<Self> {
        let bytes = Bytes(data);
        if is_64_bit {
            bytes.read(offset).map(Self::Pe64)
        } else {
            bytes.read(offset).map(Self::Pe32)
        }
    }

    pub fn is_64_bit(&self) -> bool {
        matches!(self, Self::Pe64(_))
    }

    /// Size of the fixed part, where the data directories start.
    pub fn size(&self) -> usize {
        match self {
            Self::Pe32(_) => ImageOptionalHeader32::SIZE,
            Self::Pe64(_) => ImageOptionalHeader64::SIZE,
        }
    }

    /// The base of the data section, which only 32 bit files have.
    pub fn base_of_data(&self) -> Option<Rva> {
        match self {
            Self::Pe32(h) => Some(h.base_of_data()),
            Self::Pe64(_) => None,
        }
    }
}

/// Offsets of fields that are the same in both layouts.
pub(crate) mod field_offset {
    #[cfg(feature = "authenticode")]
    pub const CHECK_SUM: usize = 0x40;
    pub const SIZE_OF_IMAGE: usize = 0x38;
}

pe_enum! {
    /// The optional header magic, which tells the bitness of the file.
    pub enum MagicType: u16 {
        Bit32 = 0x10b,
        Bit64 = 0x20b,
        Rom = 0x107,
    }
}

pe_enum! {
    /// The subsystem required to run the file.
    pub enum SubsystemType: u16, other = "Unknown Subsystem" {
        Unknown = 0 => "Unknown Subsystem",
        Native = 1 => "Native",
        WindowsGui = 2 => "Windows GUI",
        WindowsCui = 3 => "Windows CUI",
        Os2Cui = 5 => "OS/2 CUI",
        PosixCui = 7 => "POSIX CUI",
        NativeWindows = 8 => "Native Windows",
        WindowsCeGui = 9 => "Windows CE CUI",
        EfiApplication = 10 => "EFI application",
        EfiBootServiceDriver = 11 => "EFI boot service driver",
        EfiRuntimeDriver = 12 => "EFI runtime service driver",
        EfiRom = 13 => "EFI ROM image",
        Xbox = 14 => "XBox",
        WindowsBootApplication = 16 => "Windows boot application",
    }
}

bitflags::bitflags! {
    /// DLL characteristics of the optional header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DllCharacteristics: u16 {
        const HIGH_ENTROPY_VA = 0x0020;
        const DYNAMIC_BASE = 0x0040;
        const FORCE_INTEGRITY = 0x0080;
        const NX_COMPAT = 0x0100;
        const NO_ISOLATION = 0x0200;
        const NO_SEH = 0x0400;
        const NO_BIND = 0x0800;
        const APP_CONTAINER = 0x1000;
        const WDM_DRIVER = 0x2000;
        const GUARD_CF = 0x4000;
        const TERMINAL_SERVER_AWARE = 0x8000;
    }
}

impl From<u16> for DllCharacteristics {
    fn from(bits: u16) -> Self {
        Self::from_bits_retain(bits)
    }
}
