//! Editing of PE files: adding and removing sections, adding imports.

mod import;
mod section;

use alloc::vec::Vec;

pub use import::AdditionalImport;

use crate::PeFile;
use crate::error::{Error, Result};

/// Edits a PE file held in memory. [`PeFile`] is read-only; the editor owns the data, applies
/// changes and hands out a fresh [`PeFile`] view or the edited bytes.
///
/// Every edit changes the hashed content of the file, so an existing Authenticode signature is
/// invalid afterwards. The checksum in the optional header is not updated.
///
/// ```no_run
/// use pers::editor::PeEditor;
///
/// let mut editor = PeEditor::new(std::fs::read("app.exe")?)?;
/// editor.add_import("gdi32.dll", "StartPage")?;
/// std::fs::write("app_patched.exe", editor.into_bytes())?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeEditor {
    data: Vec<u8>,
}

impl PeEditor {
    /// Take ownership of the data of a valid PE file.
    pub fn new(data: Vec<u8>) -> Result<Self> {
        PeFile::parse(&data)?;
        Ok(Self { data })
    }

    /// A view on the current state of the file.
    pub fn pe(&self) -> Result<PeFile<'_>> {
        PeFile::parse(&self.data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        let data_length = self.data.len();
        let target = offset
            .checked_add(bytes.len())
            .and_then(|end| self.data.get_mut(offset..end))
            .ok_or(Error::OutOfBounds {
                offset: offset as u64,
                length: bytes.len() as u64,
                data_length: data_length as u64,
            })?;
        target.copy_from_slice(bytes);
        Ok(())
    }

    fn write_u16(&mut self, offset: usize, value: u16) -> Result<()> {
        self.write(offset, &value.to_le_bytes())
    }

    fn write_u32(&mut self, offset: usize, value: u32) -> Result<()> {
        self.write(offset, &value.to_le_bytes())
    }
}

impl TryFrom<Vec<u8>> for PeEditor {
    type Error = Error;

    fn try_from(data: Vec<u8>) -> Result<Self> {
        Self::new(data)
    }
}

#[cfg(feature = "dotnet")]
impl PeEditor {
    /// Overwrite the extra data of the .NET tables stream header. Like in PeNet, extra data can
    /// only be changed, not added to or removed from a header.
    pub fn set_metadata_tables_extra_data(&mut self, value: Option<u32>) -> Result<()> {
        let pe = self.pe()?;
        let header = pe.metadata_tables_header()?.ok_or(Error::InvalidOperation(
            "the file has no .NET metadata tables",
        ))?;
        let (has_extra_data, offset) = (header.has_extra_data(), header.extra_data_offset());
        match (value, has_extra_data) {
            (None, false) => Ok(()),
            (Some(value), true) => self.write_u32(offset.usize(), value),
            (Some(_), false) => Err(Error::InvalidOperation("the header has no extra data")),
            (None, true) => Err(Error::InvalidOperation("extra data cannot be removed")),
        }
    }
}
