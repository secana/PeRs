//! Accessors for the structures referenced by the data directories.

use alloc::vec::Vec;

use super::PeFile;
use crate::address::{FileOffset, Va};
use crate::bytes::Bytes;
use crate::error::{Error, Result};
use crate::imp_hash::imp_hash;
use crate::pe::{
    BaseRelocations, DataDirectoryType, ExportFunction, ImageBoundImportDescriptor,
    ImageCor20Header, ImageDataDirectory, ImageDebugDirectory, ImageDelayImportDescriptor,
    ImageExportDirectory, ImageImportDescriptor, ImageThunkData, ImportContext, ImportFunction,
    ImportThunks, LoadConfigDirectory, ResourceDirectory, RuntimeFunction, SubsystemType,
    TlsDirectory, WinCertificate, parse_descriptors, parse_export_functions,
};

impl<'a> PeFile<'a> {
    pub fn data_directory(&self, t: DataDirectoryType) -> &'a ImageDataDirectory {
        self.nt_headers.data_directory(t)
    }

    /// File offset of the structure a data directory points to. `Ok(None)` if the directory
    /// has no address. The headers are mapped 1:1, so RVAs inside them are file offsets; bound
    /// import tables are typically stored there.
    fn directory_offset(&self, t: DataDirectoryType) -> Result<Option<usize>> {
        let rva = self.data_directory(t).virtual_address();
        if rva.get() == 0 {
            return Ok(None);
        }
        let offset = if rva.get() < self.nt_headers.optional_header.size_of_headers() {
            FileOffset(rva.get())
        } else {
            self.section_headers()?.rva_to_offset(rva)?
        };
        if offset.usize() > self.data.len() {
            return Err(Error::OutOfBounds {
                offset: offset.get() as u64,
                length: 0,
                data_length: self.data.len() as u64,
            });
        }
        Ok(Some(offset.usize()))
    }

    /// Parse the structure a data directory points to, `Ok(None)` if the directory is absent.
    fn parse_directory<T>(
        &self,
        t: DataDirectoryType,
        parse: impl FnOnce(usize) -> Result<T>,
    ) -> Result<Option<T>> {
        self.directory_offset(t)?.map(parse).transpose()
    }

    pub fn export_directory(&self) -> Result<Option<&'a ImageExportDirectory>> {
        self.parse_directory(DataDirectoryType::Export, |o| {
            ImageExportDirectory::parse(self.data, o)
        })
    }

    pub fn exported_functions(&self) -> Result<Option<Vec<ExportFunction<'a>>>> {
        let Some(directory) = self.export_directory()? else {
            return Ok(None);
        };
        if directory.address_of_functions().get() == 0 {
            return Ok(None);
        }
        let export = self.data_directory(DataDirectoryType::Export);
        parse_export_functions(self.data, directory, self.section_headers()?, export).map(Some)
    }

    pub fn import_descriptors(&self) -> Result<Option<Vec<&'a ImageImportDescriptor>>> {
        self.parse_directory(DataDirectoryType::Import, |o| {
            parse_descriptors(self.data, o, ImageImportDescriptor::is_terminator)
        })
    }

    pub fn imported_functions(&self) -> Result<Option<Vec<ImportFunction<'a>>>> {
        let Some(descriptors) = self.import_descriptors()? else {
            return Ok(None);
        };
        let modules = descriptors.into_iter().map(|d| ImportThunks {
            name: d.name(),
            thunk_table: match d.original_first_thunk().get() {
                0 => d.first_thunk(),
                _ => d.original_first_thunk(),
            },
            iat_base: d.first_thunk(),
        });
        self.import_functions(modules, DataDirectoryType::Iat)
            .map(Some)
    }

    pub fn delay_import_descriptors(&self) -> Result<Option<Vec<&'a ImageDelayImportDescriptor>>> {
        self.parse_directory(DataDirectoryType::DelayImport, |o| {
            parse_descriptors(self.data, o, ImageDelayImportDescriptor::is_terminator)
        })
    }

    pub fn delay_imported_functions(&self) -> Result<Option<Vec<ImportFunction<'a>>>> {
        let Some(descriptors) = self.delay_import_descriptors()? else {
            return Ok(None);
        };
        let modules = descriptors.into_iter().map(|d| ImportThunks {
            name: d.name(),
            thunk_table: d.import_name_table(),
            iat_base: d.import_name_table(),
        });
        self.import_functions(modules, DataDirectoryType::DelayImport)
            .map(Some)
    }

    pub fn bound_import_descriptor(&self) -> Result<Option<&'a ImageBoundImportDescriptor>> {
        self.parse_directory(DataDirectoryType::BoundImport, |o| {
            ImageBoundImportDescriptor::parse(self.data, o)
        })
    }

    /// The blocks of the relocation directory.
    pub fn base_relocations(&self) -> Result<Option<BaseRelocations<'a>>> {
        let size = self.data_directory(DataDirectoryType::BaseReloc).size();
        self.parse_directory(DataDirectoryType::BaseReloc, |o| {
            Ok(BaseRelocations::new(self.data, o, size))
        })
    }

    /// The runtime functions of the exception directory, `Ok(None)` for 32 bit files.
    pub fn exception_directory(&self) -> Result<Option<&'a [RuntimeFunction]>> {
        if !self.is_64_bit_layout() {
            return Ok(None);
        }
        let size = self.data_directory(DataDirectoryType::Exception).size() as usize;
        self.parse_directory(DataDirectoryType::Exception, |o| {
            Bytes(self.data).read_slice(o, size / RuntimeFunction::SIZE)
        })
    }

    pub fn debug_directory(&self) -> Result<Option<&'a [ImageDebugDirectory]>> {
        let size = self.data_directory(DataDirectoryType::Debug).size() as usize;
        self.parse_directory(DataDirectoryType::Debug, |o| {
            Bytes(self.data).read_slice(o, size / ImageDebugDirectory::SIZE)
        })
    }

    pub fn tls_directory(&self) -> Result<Option<TlsDirectory<'a>>> {
        let is_64_bit = self.is_64_bit_layout();
        self.parse_directory(DataDirectoryType::Tls, |o| {
            TlsDirectory::parse(self.data, o, is_64_bit)
        })
    }

    /// The virtual addresses of the TLS callbacks.
    pub fn tls_callbacks(&self) -> Result<Option<Vec<Va>>> {
        let Some(directory) = self.tls_directory()? else {
            return Ok(None);
        };
        let is_64_bit = self.is_64_bit_layout();
        let start = self
            .section_headers()?
            .va_to_offset(Va(directory.address_of_call_backs()))?;
        let bytes = Bytes(self.data);
        let mut callbacks = Vec::new();
        for index in 0u32.. {
            let step = index.wrapping_mul(ImageThunkData::size(is_64_bit) as u32);
            match bytes.pointer(start.get().wrapping_add(step) as usize, is_64_bit)? {
                0 => break,
                callback => callbacks.push(Va(callback)),
            }
        }
        Ok(Some(callbacks))
    }

    pub fn load_config_directory(&self) -> Result<Option<LoadConfigDirectory>> {
        let is_64_bit = self.is_64_bit_layout();
        self.parse_directory(DataDirectoryType::LoadConfig, |o| {
            LoadConfigDirectory::parse(self.data, o, is_64_bit)
        })
    }

    /// The COM descriptor (CLI header) of .NET assemblies.
    pub fn com_descriptor(&self) -> Result<Option<&'a ImageCor20Header>> {
        self.parse_directory(DataDirectoryType::ComDescriptor, |o| {
            ImageCor20Header::parse(self.data, o)
        })
    }

    /// The WIN_CERTIFICATE of the security directory, whose address is a file offset.
    pub fn win_certificate(&self) -> Result<Option<WinCertificate<'a>>> {
        let offset = FileOffset(
            self.data_directory(DataDirectoryType::Security)
                .virtual_address()
                .get(),
        );
        if offset.get() == 0 {
            return Ok(None);
        }
        WinCertificate::parse(self.data, offset.usize()).map(Some)
    }

    /// The root of the resource tree.
    pub fn resource_directory(&self) -> Result<Option<ResourceDirectory<'a>>> {
        let size = self.data_directory(DataDirectoryType::Resource).size() as usize;
        self.parse_directory(DataDirectoryType::Resource, |o| {
            ResourceDirectory::parse(self.data, o, o, size)
        })
    }

    /// The import hash (ImpHash) of the imported functions, `Ok(None)` without imports.
    pub fn imp_hash(&self) -> Result<Option<[u8; 16]>> {
        Ok(self.imported_functions()?.as_deref().and_then(imp_hash))
    }

    /// True if the file is a kernel driver: native subsystem and imports from `ntoskrnl.exe`.
    pub fn is_driver(&self) -> bool {
        self.nt_headers.optional_header.subsystem() == SubsystemType::Native
            && self
                .imported_functions()
                .ok()
                .flatten()
                .is_some_and(|imports| imports.iter().any(|i| i.dll == "ntoskrnl.exe"))
    }

    /// The functions of import or delay import modules. IAT offsets are relative to the address
    /// of the `iat` directory.
    fn import_functions(
        &self,
        modules: impl Iterator<Item = ImportThunks>,
        iat: DataDirectoryType,
    ) -> Result<Vec<ImportFunction<'a>>> {
        let context = ImportContext {
            data: self.data,
            sections: self.section_headers()?,
            iat: self.data_directory(iat).virtual_address(),
            is_64_bit: self.is_64_bit_layout(),
        };
        context.parse_functions(modules)
    }

    /// True if the optional header uses the 64 bit layout, which decides the size of thunks and
    /// pointers in the data directories.
    pub(crate) fn is_64_bit_layout(&self) -> bool {
        self.nt_headers.optional_header.is_64_bit()
    }
}
