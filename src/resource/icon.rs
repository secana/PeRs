use alloc::borrow::Cow;
use alloc::vec::Vec;

use zerocopy::little_endian::{U16, U32};

use crate::bytes::Bytes;
use crate::error::Result;

const ICO_HEADER_SIZE: usize = 6;
const ICO_DIRECTORY_SIZE: usize = 16;
const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

/// An icon resource (RT_ICON): a BMP without file header or a PNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Icon<'a> {
    /// The resource ID, referenced by group icon directory entries.
    pub id: u32,
    pub data: &'a [u8],
}

impl<'a> Icon<'a> {
    /// The icon as `.ico` file. PNG icons are borrowed unchanged, BMP icons get an ICO header
    /// and directory. `None` if the data is too short to be an icon.
    pub fn to_ico(&self) -> Option<Cow<'a, [u8]>> {
        let raw = self.data;
        if raw.starts_with(&PNG_SIGNATURE) {
            return Some(Cow::Borrowed(raw));
        }
        if raw.len() <= 32 {
            return None;
        }
        let mut ico = Vec::with_capacity(ICO_HEADER_SIZE + ICO_DIRECTORY_SIZE + raw.len());
        // Reserved, type (1 = icon), number of images.
        ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
        ico.extend_from_slice(&ico_directory(raw));
        ico.extend_from_slice(raw);
        Some(Cow::Owned(ico))
    }
}

fn ico_directory(raw: &[u8]) -> [u8; ICO_DIRECTORY_SIZE] {
    let mut directory = [0u8; ICO_DIRECTORY_SIZE];
    // Icons are square. The BITMAPINFOHEADER height includes the opacity mask and is not used.
    directory[0] = raw[4];
    directory[1] = raw[4];
    directory[2] = raw[32];
    directory[4] = raw[12];
    directory[6] = raw[14];
    directory[8..12].copy_from_slice(&(raw.len() as u32).to_le_bytes());
    directory[12..16]
        .copy_from_slice(&((ICO_HEADER_SIZE + ICO_DIRECTORY_SIZE) as u32).to_le_bytes());
    directory
}

/// A group icon directory (RT_GROUP_ICON), which references icons by ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupIconDirectory<'a> {
    pub id_reserved: u16,
    pub id_type: u16,
    pub id_count: u16,
    /// The entries that fit into the resource. Corrupted counts are capped.
    pub entries: &'a [GroupIconDirectoryEntry],
}

impl<'a> GroupIconDirectory<'a> {
    /// Parse the directory of a resource with `size` bytes at `offset`. Only the entries which
    /// fit into the resource and the file are read.
    pub fn parse(data: &'a [u8], offset: usize, size: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let id_count = bytes.u16(offset + 4)?;
        let end = offset.saturating_add(size).min(data.len());
        let fitting = end.saturating_sub(offset + 6) / GroupIconDirectoryEntry::SIZE;
        Ok(Self {
            id_reserved: bytes.u16(offset)?,
            id_type: bytes.u16(offset + 2)?,
            id_count,
            entries: bytes.read_slice(offset + 6, (id_count as usize).min(fitting))?,
        })
    }
}

pe_struct! {
    /// A GRPICONDIRENTRY: the description of one icon of a group.
    pub struct GroupIconDirectoryEntry {
        b_width: u8 => u8,
        b_height: u8 => u8,
        b_color_count: u8 => u8,
        b_reserved: u8 => u8,
        w_planes: U16 => u16,
        w_bit_count: U16 => u16,
        dw_bytes_in_res: U32 => u32,
        /// ID of the icon resource.
        n_id: U16 => u16,
    }
}

impl GroupIconDirectoryEntry {
    /// All icons with the ID of this entry.
    pub fn associated_icons<'i, 'a>(
        &self,
        icons: &'i [Icon<'a>],
    ) -> impl Iterator<Item = &'i Icon<'a>> {
        let id = self.n_id() as u32;
        icons.iter().filter(move |icon| icon.id == id)
    }
}
