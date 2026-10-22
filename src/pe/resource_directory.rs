use alloc::string::String;
use alloc::vec::Vec;

use zerocopy::little_endian::{U16, U32};

use crate::address::Rva;
use crate::bytes::Bytes;
use crate::error::Result;

pe_struct! {
    /// The header of an IMAGE_RESOURCE_DIRECTORY node.
    pub struct ImageResourceDirectory {
        characteristics: U32 => u32,
        time_date_stamp: U32 => u32,
        major_version: U16 => u16,
        minor_version: U16 => u16,
        number_of_name_entries: U16 => u16,
        number_of_id_entries: U16 => u16,
    }
}

pe_struct! {
    /// An IMAGE_RESOURCE_DIRECTORY_ENTRY. It points to a sub directory or to a data entry.
    pub struct ImageResourceDirectoryEntry {
        name: U32 => u32,
        offset_to_data: U32 => u32,
    }
}

impl ImageResourceDirectoryEntry {
    pub fn is_named_entry(&self) -> bool {
        self.name() & 0x8000_0000 != 0
    }

    pub fn is_id_entry(&self) -> bool {
        !self.is_named_entry()
    }

    pub fn id(&self) -> u32 {
        self.name() & 0xFFFF
    }

    /// Offset of the name string relative to the resource directory.
    pub fn name_offset(&self) -> u32 {
        self.name() & 0x7FFF_FFFF
    }

    pub fn data_is_directory(&self) -> bool {
        self.offset_to_data() & 0x8000_0000 != 0
    }

    /// Offset of the sub directory or data entry relative to the resource directory.
    pub fn offset_to_directory(&self) -> u32 {
        self.offset_to_data() & 0x7FFF_FFFF
    }
}

pe_struct! {
    /// An IMAGE_RESOURCE_DATA_ENTRY, the leaf of the resource tree.
    pub struct ImageResourceDataEntry {
        offset_to_data: U32 => Rva,
        size: U32 => u32,
        code_page: U32 => u32,
        reserved: U32 => u32,
    }
}

/// An IMAGE_RESOURCE_DIR_STRING_U: a length prefixed UTF-16 string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageResourceDirStringU {
    pub length: u16,
    pub name_string: String,
}

impl ImageResourceDirStringU {
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let length = bytes.u16(offset)?;
        Ok(Self {
            length,
            name_string: bytes.utf16_string_with_length(offset + 2, length as usize)?,
        })
    }
}

/// The name of a resource directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceName {
    Id(u32),
    Name(String),
}

/// The position of the resource directory, which all offsets in the tree are relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourceRoot<'a> {
    data: &'a [u8],
    offset: usize,
    size: usize,
}

/// A node of the resource tree. Sub directories and data entries are parsed on access.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceDirectory<'a> {
    pub header: &'a ImageResourceDirectory,
    /// The entries of the node. Parsing stops at the first named entry without a readable name
    /// and at the first entry pointing outside of the resource directory.
    pub entries: Vec<ResourceEntry<'a>>,
}

/// An entry of a resource directory node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceEntry<'a> {
    pub raw: &'a ImageResourceDirectoryEntry,
    pub name: ResourceName,
    root: ResourceRoot<'a>,
}

impl<'a> ResourceDirectory<'a> {
    /// Parse the node at `offset`. `root_offset` and `root_size` describe the whole resource
    /// directory.
    pub fn parse(
        data: &'a [u8],
        offset: usize,
        root_offset: usize,
        root_size: usize,
    ) -> Result<Self> {
        let root = ResourceRoot {
            data,
            offset: root_offset,
            size: root_size,
        };
        let header = ImageResourceDirectory::parse(data, offset)?;
        let count =
            header.number_of_name_entries() as usize + header.number_of_id_entries() as usize;
        let raw_entries: Vec<&ImageResourceDirectoryEntry> = (0..count)
            .map(|i| {
                ImageResourceDirectoryEntry::parse(
                    data,
                    offset + ImageResourceDirectory::SIZE + i * 8,
                )
            })
            .collect::<Result<_>>()?;
        let entries = raw_entries
            .into_iter()
            .map_while(|raw| ResourceEntry::new(raw, root))
            .collect();
        Ok(Self { header, entries })
    }
}

impl<'a> ResourceEntry<'a> {
    fn new(raw: &'a ImageResourceDirectoryEntry, root: ResourceRoot<'a>) -> Option<Self> {
        let name = if raw.is_named_entry() {
            let name =
                ImageResourceDirStringU::parse(root.data, root.offset + raw.name_offset() as usize)
                    .ok()?
                    .name_string;
            (name != "unknown").then_some(ResourceName::Name(name))?
        } else {
            ResourceName::Id(raw.id())
        };
        if raw.offset_to_directory() as usize > root.size {
            return None;
        }
        Some(Self { raw, name, root })
    }

    pub fn id(&self) -> Option<u32> {
        match self.name {
            ResourceName::Id(id) => Some(id),
            ResourceName::Name(_) => None,
        }
    }

    /// The sub directory this entry points to.
    pub fn directory(&self) -> Result<ResourceDirectory<'a>> {
        let offset = self.root.offset + self.raw.offset_to_directory() as usize;
        ResourceDirectory::parse(self.root.data, offset, self.root.offset, self.root.size)
    }

    /// The data entry this entry points to.
    pub fn data_entry(&self) -> Result<&'a ImageResourceDataEntry> {
        ImageResourceDataEntry::parse(
            self.root.data,
            self.root.offset + self.raw.offset_to_data() as usize,
        )
    }
}

pe_enum! {
    /// Resource type IDs.
    pub enum ResourceType: u32 {
        Cursor = 1,
        Bitmap = 2,
        Icon = 3,
        Menu = 4,
        Dialog = 5,
        String = 6,
        FontDirectory = 7,
        Font = 8,
        Accelerator = 9,
        RcData = 10,
        MessageTable = 11,
        GroupCursor = 12,
        GroupIcon = 14,
        Version = 16,
        DlgInclude = 17,
        PlugAndPlay = 19,
        Vxd = 20,
        AnimatedCursor = 21,
        AnimatedIcon = 22,
        Html = 23,
        Manifest = 24,
    }
}
