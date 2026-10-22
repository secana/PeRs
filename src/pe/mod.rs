//! Native PE structures.

mod certificate;
mod cor20;
mod data_directory;
mod debug;
mod dos_header;
mod exception;
mod export;
mod file_header;
mod import;
mod load_config;
mod nt_headers;
mod optional_header;
mod relocation;
mod resource_directory;
mod section;
mod tls;

pub use certificate::*;
pub use cor20::*;
pub use data_directory::*;
pub use debug::*;
pub use dos_header::*;
pub use exception::*;
pub use export::{ExportFunction, ImageExportDirectory};
pub use file_header::*;
pub use import::{
    ImageBoundImportDescriptor, ImageDelayImportDescriptor, ImageImportByName,
    ImageImportDescriptor, ImageThunkData, ImportFunction,
};
pub use load_config::*;
pub use nt_headers::*;
pub use optional_header::*;
pub use relocation::*;
pub use resource_directory::*;
pub use section::*;
pub use tls::*;

pub(crate) use export::parse_export_functions;
pub(crate) use import::{ImportContext, ImportThunks, parse_descriptors};

const _: () = {
    assert!(ImageDosHeader::SIZE == 0x40);
    assert!(ImageFileHeader::SIZE == 0x14);
    assert!(ImageOptionalHeader32::SIZE == 0x60);
    assert!(ImageOptionalHeader64::SIZE == 0x70);
    assert!(ImageDataDirectory::SIZE == 0x8);
    assert!(ImageSectionHeader::SIZE == 0x28);
    assert!(ImageExportDirectory::SIZE == 0x28);
    assert!(ImageImportDescriptor::SIZE == 0x14);
    assert!(ImageDelayImportDescriptor::SIZE == 0x20);
    assert!(ImageBoundImportDescriptor::SIZE == 0x8);
    assert!(RuntimeFunction::SIZE == 0xC);
    assert!(ImageDebugDirectory::SIZE == 28);
    assert!(ImageTlsDirectory32::SIZE == 0x18);
    assert!(ImageTlsDirectory64::SIZE == 0x28);
    assert!(ImageLoadConfigDirectory32::SIZE == 0xC0);
    assert!(ImageLoadConfigDirectory64::SIZE == 0x140);
    assert!(ImageCor20Header::SIZE == 0x48);
};
