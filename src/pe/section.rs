use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use zerocopy::little_endian::{U16, U32};

use crate::address::{FileOffset, Rva, Va};
use crate::bytes::Bytes;
use crate::error::{Error, Result};

pe_struct! {
    /// An IMAGE_SECTION_HEADER entry of the section table.
    pub struct ImageSectionHeader {
        raw_name: [u8; 8] => [u8; 8],
        virtual_size: U32 => u32,
        virtual_address: U32 => Rva,
        size_of_raw_data: U32 => u32,
        pointer_to_raw_data: U32 => FileOffset,
        pointer_to_relocations: U32 => u32,
        pointer_to_linenumbers: U32 => u32,
        number_of_relocations: U16 => u16,
        number_of_linenumbers: U16 => u16,
        characteristics: U32 => SectionCharacteristics,
    }
}

impl ImageSectionHeader {
    /// The UTF-8 decoded name without trailing zero bytes.
    pub fn name(&self) -> Cow<'_, str> {
        let name = &self.raw_name;
        let end = name.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        String::from_utf8_lossy(&name[..end])
    }

    /// The size used to map RVAs. Some linkers (e.g. Watcom) set `VirtualSize` to 0, in which
    /// case `SizeOfRawData` is used.
    fn mapped_size(&self) -> u32 {
        match self.virtual_size() {
            0 => self.size_of_raw_data(),
            size => size,
        }
    }

    fn contains_rva(&self, rva: Rva, inclusive_end: bool) -> bool {
        contains(
            self.virtual_address().get(),
            self.mapped_size(),
            rva.get(),
            inclusive_end,
        )
    }

    fn contains_offset(&self, offset: FileOffset, inclusive_end: bool) -> bool {
        contains(
            self.pointer_to_raw_data().get(),
            self.size_of_raw_data(),
            offset.get(),
            inclusive_end,
        )
    }
}

/// True if `value` is in `start..start + size`. The end wraps at 32 bit like in PeNet.
fn contains(start: u32, size: u32, value: u32, inclusive_end: bool) -> bool {
    let end = start.wrapping_add(size) as u64;
    let value = value as u64;
    value >= start as u64 && (value < end || (inclusive_end && value == end))
}

bitflags::bitflags! {
    /// Section characteristics. The alignment is a 4 bit field, see
    /// [`SectionCharacteristics::alignment`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SectionCharacteristics: u32 {
        const TYPE_NO_PAD = 0x0000_0008;
        const CNT_CODE = 0x0000_0020;
        const CNT_INITIALIZED_DATA = 0x0000_0040;
        const CNT_UNINITIALIZED_DATA = 0x0000_0080;
        const LNK_OTHER = 0x0000_0100;
        const LNK_INFO = 0x0000_0200;
        const LNK_REMOVE = 0x0000_0800;
        const LNK_COMDAT = 0x0000_1000;
        const NO_DEFER_SPEC_EXC = 0x0000_4000;
        const GPREL = 0x0000_8000;
        const MEM_PURGEABLE = 0x0002_0000;
        const MEM_LOCKED = 0x0004_0000;
        const MEM_PRELOAD = 0x0008_0000;
        const LNK_NRELOC_OVFL = 0x0100_0000;
        const MEM_DISCARDABLE = 0x0200_0000;
        const MEM_NOT_CACHED = 0x0400_0000;
        const MEM_NOT_PAGED = 0x0800_0000;
        const MEM_SHARED = 0x1000_0000;
        const MEM_EXECUTE = 0x2000_0000;
        const MEM_READ = 0x4000_0000;
        const MEM_WRITE = 0x8000_0000;
    }
}

impl SectionCharacteristics {
    const ALIGNMENT_MASK: u32 = 0x00F0_0000;

    /// The alignment of an object file section in bytes, `None` if no alignment is set.
    pub fn alignment(self) -> Option<u32> {
        match (self.bits() & Self::ALIGNMENT_MASK) >> 20 {
            0 | 15 => None,
            n => Some(1 << (n - 1)),
        }
    }
}

impl From<u32> for SectionCharacteristics {
    fn from(bits: u32) -> Self {
        Self::from_bits_retain(bits)
    }
}

/// The section headers, sorted by virtual address like in PeNet, with address conversions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionTable<'a> {
    sections: Vec<&'a ImageSectionHeader>,
    image_base: u64,
}

impl<'a> SectionTable<'a> {
    /// Parse `count` section headers at `offset`.
    pub fn parse(data: &'a [u8], offset: usize, count: u16, image_base: u64) -> Result<Self> {
        let headers: &[ImageSectionHeader] = Bytes(data).read_slice(offset, count as usize)?;
        let mut sections: Vec<_> = headers.iter().collect();
        sections.sort_by_key(|s| s.virtual_address());
        Ok(Self {
            sections,
            image_base,
        })
    }

    pub fn len(&self) -> usize {
        self.sections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&'a ImageSectionHeader> {
        self.sections.get(index).copied()
    }

    pub fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = &'a ImageSectionHeader> + ExactSizeIterator + '_ {
        self.sections.iter().copied()
    }

    /// The first section with the given name.
    pub fn by_name(&self, name: &str) -> Option<&'a ImageSectionHeader> {
        self.iter().find(|s| s.name() == name)
    }

    /// The section containing an RVA: the last one with `start <= rva < end`, otherwise the first
    /// one with `start <= rva <= end`.
    pub fn section_for_rva(&self, rva: Rva) -> Option<&'a ImageSectionHeader> {
        self.iter()
            .rev()
            .find(|s| s.contains_rva(rva, false))
            .or_else(|| self.iter().find(|s| s.contains_rva(rva, true)))
    }

    pub fn rva_to_offset(&self, rva: Rva) -> Result<FileOffset> {
        let section = self.section_for_rva(rva).ok_or(Error::RvaNotMapped(rva))?;
        Ok(FileOffset(
            rva.get()
                .wrapping_sub(section.virtual_address().get())
                .wrapping_add(section.pointer_to_raw_data().get()),
        ))
    }

    /// Map a virtual address using the image base of the file.
    pub fn va_to_offset(&self, va: Va) -> Result<FileOffset> {
        self.rva_to_offset(Rva(va.get().wrapping_sub(self.image_base) as u32))
    }

    pub fn offset_to_rva(&self, offset: FileOffset) -> Result<Rva> {
        let section = self
            .iter()
            .rev()
            .find(|s| s.contains_offset(offset, false))
            .or_else(|| self.iter().find(|s| s.contains_offset(offset, true)))
            .ok_or(Error::OffsetNotMapped(offset))?;
        Ok(Rva(offset
            .get()
            .wrapping_add(section.virtual_address().get())
            .wrapping_sub(section.pointer_to_raw_data().get())))
    }
}

impl<'a, 'b> IntoIterator for &'b SectionTable<'a> {
    type Item = &'a ImageSectionHeader;
    type IntoIter = core::iter::Copied<core::slice::Iter<'b, &'a ImageSectionHeader>>;

    fn into_iter(self) -> Self::IntoIter {
        self.sections.iter().copied()
    }
}
