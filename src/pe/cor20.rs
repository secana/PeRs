use zerocopy::little_endian::{U16, U32};

use super::ImageDataDirectory;

pe_struct! {
    /// The IMAGE_COR20_HEADER (CLI header) of .NET assemblies.
    pub struct ImageCor20Header {
        cb: U32 => u32,
        major_runtime_version: U16 => u16,
        minor_runtime_version: U16 => u16,
        meta_data: ImageDataDirectory => ImageDataDirectory,
        flags: U32 => ComFlags,
        /// The entry point token, or the entry point RVA for native entry points.
        entry_point_token: U32 => u32,
        resources: ImageDataDirectory => ImageDataDirectory,
        strong_name_signature: ImageDataDirectory => ImageDataDirectory,
        code_manager_table: ImageDataDirectory => ImageDataDirectory,
        v_table_fixups: ImageDataDirectory => ImageDataDirectory,
        export_address_table_jumps: ImageDataDirectory => ImageDataDirectory,
        managed_native_header: ImageDataDirectory => ImageDataDirectory,
    }
}

bitflags::bitflags! {
    /// Flags of the CLI header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ComFlags: u32 {
        const IL_ONLY = 0x0000_0001;
        const REQUIRES_32BIT = 0x0000_0002;
        const IL_LIBRARY = 0x0000_0004;
        const STRONG_NAME_SIGNED = 0x0000_0008;
        const NATIVE_ENTRYPOINT = 0x0000_0010;
        const TRACK_DEBUG_DATA = 0x0001_0000;
    }
}

impl From<u32> for ComFlags {
    fn from(bits: u32) -> Self {
        Self::from_bits_retain(bits)
    }
}
