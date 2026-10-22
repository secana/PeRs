use alloc::string::String;
use alloc::vec::Vec;

use zerocopy::little_endian::U32;
use zerocopy::{FromZeros, IntoBytes};

use super::PeEditor;
use crate::address::Rva;
use crate::error::{Error, Result};
use crate::pe::{
    DataDirectoryType, ImageImportByName, ImageImportDescriptor, ImageThunkData,
    SectionCharacteristics,
};

const NEW_IMPORT_SECTION: &str = ".addImp";

/// Functions of one module to add to the import table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdditionalImport {
    pub module: String,
    pub functions: Vec<String>,
}

impl AdditionalImport {
    pub fn new(
        module: impl Into<String>,
        functions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            module: module.into(),
            functions: functions.into_iter().map(Into::into).collect(),
        }
    }
}

impl PeEditor {
    /// Add one imported function. Use [`add_imports`](Self::add_imports) for multiple imports,
    /// as every call adds a new section.
    pub fn add_import(&mut self, module: &str, function: &str) -> Result<()> {
        self.add_imports(&[AdditionalImport::new(module, [function])])
    }

    /// Add imports. The import descriptors are copied to a new section `.addImp`, followed by one
    /// descriptor per additional import, the module names, import by name entries and thunks.
    ///
    /// ```no_run
    /// use pers::editor::{AdditionalImport, PeEditor};
    ///
    /// let mut editor = PeEditor::new(std::fs::read("app.exe")?)?;
    /// editor.add_imports(&[
    ///     AdditionalImport::new("gdi32.dll", ["StartPage", "EndDoc"]),
    ///     AdditionalImport::new("ADVAPI32.dll", ["RegCloseKey"]),
    /// ])?;
    /// std::fs::write("app_patched.exe", editor.into_bytes())?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn add_imports(&mut self, imports: &[AdditionalImport]) -> Result<()> {
        let pe = self.pe()?;
        let thunk_size = ImageThunkData::size(pe.nt_headers().optional_header.is_64_bit());
        let directory_entry = pe
            .nt_headers()
            .data_directory_offset(DataDirectoryType::Import);
        let mut descriptors: Vec<u8> = pe
            .import_descriptors()?
            .unwrap_or_default()
            .iter()
            .flat_map(|d| d.as_bytes().to_vec())
            .collect();
        let descriptors_size =
            descriptors.len() + (imports.len() + 1) * ImageImportDescriptor::SIZE;
        let data_start = descriptors_size.next_multiple_of(thunk_size);
        let tables: Vec<ImportTables> = imports
            .iter()
            .map(|i| ImportTables::new(i, thunk_size))
            .collect();
        let data_size: usize = tables.iter().map(ImportTables::size).sum();

        self.add_section(
            NEW_IMPORT_SECTION,
            data_start + data_size,
            SectionCharacteristics::CNT_INITIALIZED_DATA
                | SectionCharacteristics::MEM_READ
                | SectionCharacteristics::MEM_WRITE,
        )?;
        let pe = self.pe()?;
        let section = pe
            .section_headers()?
            .iter()
            .rfind(|s| s.name() == NEW_IMPORT_SECTION)
            .ok_or(Error::InvalidOperation("new import section not found"))?;
        let (section_offset, section_rva) = (
            section.pointer_to_raw_data().usize(),
            section.virtual_address(),
        );

        let mut data = Vec::with_capacity(data_size);
        for table in &tables {
            let start = Rva(section_rva.get() + (data_start + data.len()) as u32);
            let (name, first_thunk) = table.write(start, &mut data);
            let mut descriptor = ImageImportDescriptor::new_zeroed();
            descriptor.name = U32::new(name.get());
            descriptor.first_thunk = U32::new(first_thunk.get());
            descriptors.extend_from_slice(descriptor.as_bytes());
        }
        descriptors.resize(data_start, 0);
        descriptors.extend_from_slice(&data);

        self.write(section_offset, &descriptors)?;
        self.write_u32(directory_entry, section_rva.get())?;
        self.write_u32(directory_entry + 4, descriptors_size as u32)
    }
}

/// The module name, import by name entries and thunk table of one additional import.
struct ImportTables {
    module_name: Vec<u8>,
    by_names: Vec<Vec<u8>>,
    thunk_size: usize,
}

impl ImportTables {
    fn new(import: &AdditionalImport, thunk_size: usize) -> Self {
        let mut module_name = crate::bytes::encode_ascii(&import.module);
        module_name.push(0);
        Self {
            module_name,
            by_names: import
                .functions
                .iter()
                .map(|f| ImageImportByName::encode(0, f))
                .collect(),
            thunk_size,
        }
    }

    fn names_size(&self) -> usize {
        self.module_name.len() + self.by_names.iter().map(Vec::len).sum::<usize>()
    }

    /// Size including the padding which aligns the thunk table.
    fn size(&self) -> usize {
        self.names_size().next_multiple_of(self.thunk_size)
            + (self.by_names.len() + 1) * self.thunk_size
    }

    /// Append the tables to `data`, whose end is at `start`. Returns the RVAs of the module name
    /// and of the thunk table.
    fn write(&self, start: Rva, data: &mut Vec<u8>) -> (Rva, Rva) {
        let base = data.len();
        let rva = |data: &Vec<u8>| Rva(start.get() + (data.len() - base) as u32);
        let name = rva(data);
        data.extend_from_slice(&self.module_name);
        let mut by_name_rvas = Vec::with_capacity(self.by_names.len());
        for by_name in &self.by_names {
            by_name_rvas.push(rva(data));
            data.extend_from_slice(by_name);
        }
        data.resize(
            base + self.names_size().next_multiple_of(self.thunk_size),
            0,
        );
        let thunks = rva(data);
        for by_name_rva in by_name_rvas.into_iter().chain([Rva(0)]) {
            data.extend_from_slice(&(by_name_rva.get() as u64).to_le_bytes()[..self.thunk_size]);
        }
        (name, thunks)
    }
}
