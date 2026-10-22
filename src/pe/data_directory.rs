use zerocopy::little_endian::U32;

use crate::address::Rva;

pe_struct! {
    /// An IMAGE_DATA_DIRECTORY entry: address and size of a table such as the import table.
    pub struct ImageDataDirectory {
        virtual_address: U32 => Rva,
        size: U32 => u32,
    }
}

impl ImageDataDirectory {
    /// The table of all 16 data directories at `offset`.
    pub fn parse_table(data: &[u8], offset: usize) -> crate::Result<&[Self]> {
        crate::bytes::Bytes(data).read_slice(offset, DataDirectoryType::COUNT)
    }

    /// True if the directory has an address and a size.
    pub fn is_present(&self) -> bool {
        self.virtual_address().get() != 0 && self.size() != 0
    }
}

/// Index of a data directory in the optional header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(usize)]
pub enum DataDirectoryType {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    /// The certificate table. Its address is a file offset, not an RVA.
    Security = 4,
    BaseReloc = 5,
    Debug = 6,
    Copyright = 7,
    GlobalPtr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    Iat = 12,
    DelayImport = 13,
    ComDescriptor = 14,
    Reserved = 15,
}

impl DataDirectoryType {
    pub const COUNT: usize = 16;
}
