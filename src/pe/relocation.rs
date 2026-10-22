use zerocopy::little_endian::U16;

use crate::address::Rva;
use crate::bytes::Bytes;
use crate::error::{Result, malformed};

/// An IMAGE_BASE_RELOCATION block: the relocations of one 4 KB page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageBaseRelocation<'a> {
    pub virtual_address: Rva,
    pub size_of_block: u32,
    entries: &'a [U16],
}

impl<'a> ImageBaseRelocation<'a> {
    /// Parse the block at `offset`. `directory_size` is the size of the relocation directory.
    pub fn parse(data: &'a [u8], offset: usize, directory_size: u32) -> Result<Self> {
        let bytes = Bytes(data);
        let virtual_address = Rva(bytes.u32(offset)?);
        let size_of_block = bytes.u32(offset + 4)?;
        if size_of_block > directory_size {
            return Err(malformed(
                "base relocation",
                "block larger than the relocation directory",
            ));
        }
        if size_of_block < 8 {
            return Err(malformed(
                "base relocation",
                "block smaller than its header",
            ));
        }
        let entries = bytes.read_slice(offset + 8, (size_of_block as usize - 8) / 2)?;
        Ok(Self {
            virtual_address,
            size_of_block,
            entries,
        })
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = RelocationEntry> + 'a {
        self.entries.iter().map(|e| RelocationEntry(e.get()))
    }
}

/// A relocation entry: the type in the upper 4 bits, the page offset in the lower 12 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationEntry(pub u16);

impl RelocationEntry {
    pub fn relocation_type(self) -> u8 {
        (self.0 >> 12) as u8
    }

    pub fn page_offset(self) -> u16 {
        self.0 & 0xFFF
    }
}

/// Iterator over the blocks of the relocation directory. Stops after the first error.
#[derive(Debug, Clone)]
pub struct BaseRelocations<'a> {
    data: &'a [u8],
    current: usize,
    end: i64,
    directory_size: u32,
}

impl<'a> BaseRelocations<'a> {
    pub(crate) fn new(data: &'a [u8], offset: usize, directory_size: u32) -> Self {
        Self {
            data,
            current: offset,
            end: offset as i64 + directory_size as i64 - 8,
            directory_size,
        }
    }
}

impl<'a> Iterator for BaseRelocations<'a> {
    type Item = Result<ImageBaseRelocation<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current as i64 >= self.end {
            return None;
        }
        let block = ImageBaseRelocation::parse(self.data, self.current, self.directory_size);
        match &block {
            Ok(block) => self.current += block.size_of_block as usize,
            Err(_) => self.end = 0,
        }
        Some(block)
    }
}
