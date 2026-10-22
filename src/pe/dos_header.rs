use zerocopy::little_endian::{U16, U32};

pe_struct! {
    /// The IMAGE_DOS_HEADER with which every PE file starts.
    pub struct ImageDosHeader {
        /// Magic "MZ" header.
        e_magic: U16 => u16,
        /// Bytes on the last page of the file.
        e_cblp: U16 => u16,
        /// Pages in the file.
        e_cp: U16 => u16,
        /// Relocations.
        e_crlc: U16 => u16,
        /// Size of the header in paragraphs.
        e_cparhdr: U16 => u16,
        /// Minimum extra paragraphs needed.
        e_minalloc: U16 => u16,
        /// Maximum extra paragraphs needed.
        e_maxalloc: U16 => u16,
        /// Initial (relative) SS value.
        e_ss: U16 => u16,
        /// Initial SP value.
        e_sp: U16 => u16,
        /// Checksum.
        e_csum: U16 => u16,
        /// Initial IP value.
        e_ip: U16 => u16,
        /// Initial (relative) CS value.
        e_cs: U16 => u16,
        /// File address of the relocation table.
        e_lfarlc: U16 => u16,
        /// Overlay number.
        e_ovno: U16 => u16,
        e_res: [U16; 4] => [u16; 4],
        /// OEM identifier.
        e_oemid: U16 => u16,
        /// OEM information.
        e_oeminfo: U16 => u16,
        e_res2: [U16; 10] => [u16; 10],
        /// File offset of the NT headers.
        e_lfanew: U32 => u32,
    }
}

impl ImageDosHeader {
    /// The `MZ` magic.
    pub const MAGIC: u16 = 0x5a4d;
}
