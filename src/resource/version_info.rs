use alloc::string::String;
use alloc::vec::Vec;

use zerocopy::little_endian::U32;

use crate::bytes::{Bytes, utf16_len};
use crate::error::Result;

/// Round `offset` up to the next 32 bit boundary.
fn align(offset: usize) -> usize {
    offset.next_multiple_of(4)
}

/// The header every version information structure starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionHeader {
    /// Length of the structure including its children.
    pub w_length: u16,
    pub w_value_length: u16,
    /// 1 for text values, 0 for binary values.
    pub w_type: u16,
    pub sz_key: String,
}

impl VersionHeader {
    fn parse(bytes: Bytes, offset: usize) -> Result<Self> {
        Ok(Self {
            w_length: bytes.u16(offset)?,
            w_value_length: bytes.u16(offset + 2)?,
            w_type: bytes.u16(offset + 4)?,
            sz_key: bytes.utf16_string(offset + 6)?,
        })
    }

    /// Offset of the value or the first child: after the zero terminated key, aligned.
    fn value_offset(&self, offset: usize) -> usize {
        align(offset + 6 + utf16_len(&self.sz_key) * 2 + 2)
    }
}

/// A structure in the version information tree.
trait Node: Sized {
    fn header(&self) -> &VersionHeader;

    /// Parse the rest of the structure after its header.
    fn with_header(bytes: Bytes, offset: usize, header: VersionHeader) -> Result<Self>;

    fn parse(bytes: Bytes, offset: usize) -> Result<Self> {
        let header = VersionHeader::parse(bytes, offset)?;
        Self::with_header(bytes, offset, header)
    }
}

/// Implement [`Node`] for a structure whose children follow its key.
macro_rules! parent_node {
    ($name:ident, $children:ident) => {
        impl Node for $name {
            fn header(&self) -> &VersionHeader {
                &self.header
            }

            fn with_header(bytes: Bytes, offset: usize, header: VersionHeader) -> Result<Self> {
                let end = offset + header.w_length as usize;
                let $children = parse_children(bytes, header.value_offset(offset), end)?;
                Ok(Self { header, $children })
            }
        }
    };
}

/// Parse aligned children until `end` or a child with length 0.
fn parse_children<T: Node>(bytes: Bytes, first_offset: usize, end: usize) -> Result<Vec<T>> {
    let mut children = Vec::new();
    let mut current = align(first_offset);
    while current < end {
        let child = T::parse(bytes, current)?;
        let length = child.header().w_length as usize;
        if length == 0 {
            break;
        }
        current = align(current + length);
        children.push(child);
    }
    Ok(children)
}

/// The VS_VERSIONINFO resource.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VsVersionInfo<'a> {
    pub header: VersionHeader,
    pub fixed_file_info: Option<&'a VsFixedFileInfo>,
    pub string_file_info: Option<StringFileInfo>,
    pub var_file_info: Option<VarFileInfo>,
}

impl<'a> VsVersionInfo<'a> {
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let header = VersionHeader::parse(bytes, offset)?;
        let fixed_file_info_offset = header.value_offset(offset);
        let end = offset + header.w_length as usize;
        let first_child = align(fixed_file_info_offset + header.w_value_length as usize);

        // StringFileInfo and VarFileInfo can appear in either order.
        let mut string_file_info = None;
        let mut var_file_info = None;
        let mut current = first_child;
        while current < end {
            let Ok(child) = VersionHeader::parse(bytes, current) else {
                break;
            };
            match child.sz_key.as_str() {
                "StringFileInfo" if string_file_info.is_none() => {
                    string_file_info = StringFileInfo::parse(bytes, current).ok();
                }
                "VarFileInfo" if var_file_info.is_none() => {
                    var_file_info = VarFileInfo::parse(bytes, current).ok()
                }
                _ => {}
            }
            if child.w_length == 0 {
                break;
            }
            current = align(current + child.w_length as usize);
        }

        Ok(Self {
            fixed_file_info: VsFixedFileInfo::parse(data, fixed_file_info_offset).ok(),
            header,
            string_file_info,
            var_file_info,
        })
    }
}

pe_struct! {
    /// The VS_FIXEDFILEINFO structure.
    pub struct VsFixedFileInfo {
        dw_signature: U32 => u32,
        dw_struc_version: U32 => u32,
        dw_file_version_ms: U32 => u32,
        dw_file_version_ls: U32 => u32,
        dw_product_version_ms: U32 => u32,
        dw_product_version_ls: U32 => u32,
        dw_file_flags_mask: U32 => u32,
        dw_file_flags: U32 => u32,
        dw_file_os: U32 => u32,
        dw_file_type: U32 => u32,
        dw_file_sub_type: U32 => u32,
        dw_file_date_ms: U32 => u32,
        dw_file_date_ls: U32 => u32,
    }
}

impl VsFixedFileInfo {
    /// The file version as `[major, minor, build, revision]`.
    pub fn file_version(&self) -> [u16; 4] {
        version(self.dw_file_version_ms(), self.dw_file_version_ls())
    }

    /// The product version as `[major, minor, build, revision]`.
    pub fn product_version(&self) -> [u16; 4] {
        version(self.dw_product_version_ms(), self.dw_product_version_ls())
    }
}

fn version(ms: u32, ls: u32) -> [u16; 4] {
    [(ms >> 16) as u16, ms as u16, (ls >> 16) as u16, ls as u16]
}

/// The StringFileInfo structure with one string table per language.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StringFileInfo {
    pub header: VersionHeader,
    pub string_tables: Vec<StringTable>,
}

parent_node!(StringFileInfo, string_tables);

/// The version strings of one language.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StringTable {
    /// The key is the language and code page as hex string, e.g. `040904B0`.
    pub header: VersionHeader,
    pub strings: Vec<VersionString>,
}

impl StringTable {
    /// Value of a predefined version string.
    pub fn get(&self, key: VersionKey) -> Option<&str> {
        self.value(key.as_str())
    }

    /// Value of the first string with the given key.
    pub fn value(&self, key: &str) -> Option<&str> {
        self.strings
            .iter()
            .find(|s| s.header.sz_key == key)
            .map(|s| s.value.as_str())
    }

    /// All key value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.strings
            .iter()
            .map(|s| (s.header.sz_key.as_str(), s.value.as_str()))
    }
}

parent_node!(StringTable, strings);

/// One key value pair of a string table (the `String` structure).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionString {
    pub header: VersionHeader,
    pub value: String,
}

impl Node for VersionString {
    fn with_header(bytes: Bytes, offset: usize, header: VersionHeader) -> Result<Self> {
        let value = bytes.utf16_string(header.value_offset(offset))?;
        Ok(Self { header, value })
    }

    fn header(&self) -> &VersionHeader {
        &self.header
    }
}

/// The predefined keys of version strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VersionKey {
    Comments,
    CompanyName,
    FileDescription,
    FileVersion,
    InternalName,
    LegalCopyright,
    LegalTrademarks,
    OriginalFilename,
    PrivateBuild,
    ProductName,
    ProductVersion,
    SpecialBuild,
}

impl VersionKey {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Comments => "Comments",
            Self::CompanyName => "CompanyName",
            Self::FileDescription => "FileDescription",
            Self::FileVersion => "FileVersion",
            Self::InternalName => "InternalName",
            Self::LegalCopyright => "LegalCopyright",
            Self::LegalTrademarks => "LegalTrademarks",
            Self::OriginalFilename => "OriginalFilename",
            Self::PrivateBuild => "PrivateBuild",
            Self::ProductName => "ProductName",
            Self::ProductVersion => "ProductVersion",
            Self::SpecialBuild => "SpecialBuild",
        }
    }
}

/// The VarFileInfo structure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VarFileInfo {
    pub header: VersionHeader,
    pub children: Vec<Var>,
}

parent_node!(VarFileInfo, children);

/// A Var structure, e.g. `Translation` with language and code page pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Var {
    pub header: VersionHeader,
    pub value: Vec<u32>,
}

impl Node for Var {
    fn with_header(bytes: Bytes, offset: usize, header: VersionHeader) -> Result<Self> {
        let start = header.value_offset(offset);
        let values: &[U32] = bytes.read_slice(start, header.w_value_length as usize / 4)?;
        let value = values.iter().map(|v| v.get()).collect();
        Ok(Self { header, value })
    }

    fn header(&self) -> &VersionHeader {
        &self.header
    }
}
