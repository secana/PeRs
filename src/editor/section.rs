use alloc::vec;
use alloc::vec::Vec;

use zerocopy::little_endian::U32;
use zerocopy::{FromZeros, IntoBytes};

use super::PeEditor;
use crate::PeFile;
use crate::error::{Error, Result};
use crate::pe::{ImageDataDirectory, ImageSectionHeader, SectionCharacteristics, field_offset};

/// The name as the 8 byte field of a section header.
fn encode_name(name: &str) -> Result<[u8; 8]> {
    let bytes = name.as_bytes();
    if bytes.len() > 8 {
        return Err(Error::InvalidOperation(
            "section names have at most 8 bytes",
        ));
    }
    let mut raw = [0u8; 8];
    raw[..bytes.len()].copy_from_slice(bytes);
    Ok(raw)
}

/// Round `value` up to a multiple of `alignment`.
fn align(value: u32, alignment: u32) -> Result<u32> {
    value
        .checked_next_multiple_of(alignment)
        .ok_or(Error::InvalidOperation("alignment overflow"))
}

/// File offset of the `NumberOfSections` field.
fn number_of_sections_offset(pe: &PeFile) -> usize {
    pe.nt_headers().offset + 4 + 2
}

/// The changes of a section removal, computed before the data is modified.
struct SectionRemoval {
    number_of_sections: u16,
    /// Start and length of the section data to remove.
    content: Option<(usize, usize)>,
    cleared_directory: Option<usize>,
    table_offset: usize,
    old_table_size: usize,
    new_table: Vec<u8>,
}

impl SectionRemoval {
    fn plan(pe: &PeFile, name: &str, remove_content: bool) -> Result<Self> {
        let nt = pe.nt_headers();
        let sections = pe.section_headers()?;
        let removed = *sections
            .by_name(name)
            .ok_or(Error::InvalidOperation("section not found"))?;
        let mut remaining: Vec<ImageSectionHeader> = sections
            .iter()
            .filter(|s| s.name() != name)
            .copied()
            .collect();

        if remove_content {
            for s in &mut remaining {
                if s.pointer_to_raw_data() > removed.pointer_to_raw_data() {
                    let pointer = s
                        .pointer_to_raw_data()
                        .get()
                        .wrapping_sub(removed.size_of_raw_data());
                    s.pointer_to_raw_data = U32::new(pointer);
                }
            }
        }
        // Extend the virtual size of the sections before the removed one to close the gap.
        for i in 1..remaining.len() {
            if remaining[i - 1].virtual_address() < removed.virtual_address() {
                let size = remaining[i]
                    .virtual_address()
                    .get()
                    .wrapping_sub(remaining[i - 1].virtual_address().get());
                remaining[i - 1].virtual_size = U32::new(size);
            }
        }

        let first_directory = nt.optional_header_offset() + nt.optional_header.size();
        Ok(Self {
            number_of_sections: nt.file_header.number_of_sections().wrapping_sub(1),
            content: remove_content.then(|| {
                (
                    removed.pointer_to_raw_data().usize(),
                    removed.size_of_raw_data() as usize,
                )
            }),
            cleared_directory: nt
                .data_directories
                .iter()
                .position(|d| {
                    d.virtual_address() == removed.virtual_address()
                        && d.size() == removed.virtual_size()
                })
                .map(|index| first_directory + index * ImageDataDirectory::SIZE),
            table_offset: nt.section_table_offset(),
            old_table_size: sections.len() * ImageSectionHeader::SIZE,
            new_table: remaining.as_bytes().to_vec(),
        })
    }
}

impl PeEditor {
    /// Add a new zero filled section of `size` bytes.
    ///
    /// ```no_run
    /// use pers::editor::PeEditor;
    /// use pers::pe::SectionCharacteristics;
    ///
    /// let mut editor = PeEditor::new(std::fs::read("app.exe")?)?;
    /// let characteristics = SectionCharacteristics::CNT_INITIALIZED_DATA | SectionCharacteristics::MEM_READ;
    /// editor.add_section(".data2", 0x1000, characteristics)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_section(
        &mut self,
        name: &str,
        size: usize,
        characteristics: SectionCharacteristics,
    ) -> Result<()> {
        self.add_section_with_content(name, &vec![0u8; size], characteristics)
    }

    /// Add a section with the given content at the end of the file and in the image. The name
    /// has at most 8 bytes. There must be space for another section header before the first
    /// section.
    pub fn add_section_with_content(
        &mut self,
        name: &str,
        content: &[u8],
        characteristics: SectionCharacteristics,
    ) -> Result<()> {
        let name = encode_name(name)?;
        let pe = self.pe()?;
        let nt = pe.nt_headers();
        let optional_header = &nt.optional_header;
        let (section_alignment, file_alignment) = (
            optional_header.section_alignment(),
            optional_header.file_alignment(),
        );
        if section_alignment == 0 || file_alignment == 0 {
            return Err(Error::InvalidOperation("alignment must not be 0"));
        }
        let number_of_sections = nt.file_header.number_of_sections();
        let header_offset =
            nt.section_table_offset() + number_of_sections as usize * ImageSectionHeader::SIZE;
        if header_offset + ImageSectionHeader::SIZE > optional_header.size_of_headers() as usize {
            return Err(Error::InvalidOperation(
                "no space for another section header",
            ));
        }
        let end_of_image = pe
            .section_headers()?
            .iter()
            .map(|s| s.virtual_address().get().saturating_add(s.virtual_size()))
            .max()
            .ok_or(Error::InvalidOperation("the file has no sections"))?;
        let content_length = u32::try_from(content.len())
            .map_err(|_| Error::InvalidOperation("section content too large"))?;
        let virtual_address = align(end_of_image, section_alignment)?;
        let pointer_to_raw_data = align(self.data.len() as u32, file_alignment)?;
        let size_of_raw_data = align(content_length, file_alignment)?;
        let size_of_image = align(
            virtual_address.saturating_add(content_length),
            section_alignment,
        )?;

        let mut section = ImageSectionHeader::new_zeroed();
        section.raw_name = name;
        section.virtual_size = U32::new(content_length);
        section.virtual_address = U32::new(virtual_address);
        section.size_of_raw_data = U32::new(size_of_raw_data);
        section.pointer_to_raw_data = U32::new(pointer_to_raw_data);
        section.characteristics = U32::new(characteristics.bits());
        let number_of_sections_offset = number_of_sections_offset(&pe);
        let size_of_image_offset = nt.optional_header_offset() + field_offset::SIZE_OF_IMAGE;

        self.data.resize(pointer_to_raw_data as usize, 0);
        self.data.extend_from_slice(content);
        self.data
            .resize((pointer_to_raw_data + size_of_raw_data) as usize, 0);
        self.write(header_offset, section.as_bytes())?;
        self.write_u16(number_of_sections_offset, number_of_sections + 1)?;
        self.write_u32(size_of_image_offset, size_of_image)
    }

    /// Remove a section. With `remove_content` the section data is removed from the file and the
    /// raw addresses of the following sections are adjusted, otherwise only the section header
    /// is removed. A data directory pointing exactly to the section is cleared.
    ///
    /// ```no_run
    /// use pers::editor::PeEditor;
    ///
    /// let mut editor = PeEditor::new(std::fs::read("app.exe")?)?;
    /// // Remove the resources: the section header and its content.
    /// editor.remove_section(".rsrc", true)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn remove_section(&mut self, name: &str, remove_content: bool) -> Result<()> {
        let pe = self.pe()?;
        let removal = SectionRemoval::plan(&pe, name, remove_content)?;
        let number_of_sections_offset = number_of_sections_offset(&pe);

        self.write_u16(number_of_sections_offset, removal.number_of_sections)?;
        if let Some((start, length)) = removal.content {
            let end = start
                .checked_add(length)
                .filter(|&end| end <= self.data.len())
                .ok_or(Error::InvalidOperation("section data outside of the file"))?;
            self.data.drain(start..end);
        }
        if let Some(offset) = removal.cleared_directory {
            self.write(offset, &[0u8; ImageDataDirectory::SIZE])?;
        }
        self.write(removal.table_offset, &vec![0u8; removal.old_table_size])?;
        self.write(removal.table_offset, &removal.new_table)
    }
}
