use alloc::borrow::Cow;
use alloc::vec::Vec;

use zerocopy::little_endian::{U16, U32};

use super::{ImageDataDirectory, SectionTable};
use crate::address::Rva;
use crate::bytes::Bytes;
use crate::error::{Result, malformed};

pe_struct! {
    /// The IMAGE_EXPORT_DIRECTORY, which describes the functions exported by the file.
    pub struct ImageExportDirectory {
        characteristics: U32 => u32,
        time_date_stamp: U32 => u32,
        major_version: U16 => u16,
        minor_version: U16 => u16,
        /// RVA of the module name.
        name: U32 => Rva,
        /// Ordinal of the first exported function.
        base: U32 => u32,
        number_of_functions: U32 => u32,
        number_of_names: U32 => u32,
        address_of_functions: U32 => Rva,
        address_of_names: U32 => Rva,
        address_of_name_ordinals: U32 => Rva,
    }
}

/// A function exported by the file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportFunction<'a> {
    pub name: Option<Cow<'a, str>>,
    pub address: Rva,
    pub ordinal: u16,
    /// Target of a forwarded export, e.g. `NTDLL.RtlEnterCriticalSection`.
    pub forward_name: Option<Cow<'a, str>>,
}

impl ExportFunction<'_> {
    pub fn is_forwarded(&self) -> bool {
        self.forward_name.as_deref().is_some_and(|n| !n.is_empty())
    }
}

/// Parse the exported functions. Names are associated through the name ordinal table; an
/// address inside the export directory marks a forwarded export.
pub(crate) fn parse_export_functions<'a>(
    data: &'a [u8],
    directory: &ImageExportDirectory,
    sections: &SectionTable<'a>,
    export_data_directory: &ImageDataDirectory,
) -> Result<Vec<ExportFunction<'a>>> {
    let bytes = Bytes(data);
    let function_table = sections
        .rva_to_offset(directory.address_of_functions())?
        .usize();
    let addresses: &[U32] =
        bytes.read_slice(function_table, directory.number_of_functions() as usize)?;
    let mut functions: Vec<_> = addresses
        .iter()
        .zip(0u32..)
        .map(|(address, i)| ExportFunction {
            name: None,
            address: Rva(address.get()),
            ordinal: i.wrapping_add(directory.base()) as u16,
            forward_name: None,
        })
        .collect();
    if directory.number_of_names() == 0 {
        return Ok(functions);
    }

    let count = directory.number_of_names() as usize;
    let names: &[U32] = bytes.read_slice(
        sections
            .rva_to_offset(directory.address_of_names())?
            .usize(),
        count,
    )?;
    let ordinals: &[U16] = bytes.read_slice(
        sections
            .rva_to_offset(directory.address_of_name_ordinals())?
            .usize(),
        count,
    )?;
    let start = export_data_directory.virtual_address().get();
    let end = start.wrapping_add(export_data_directory.size());
    for (name, ordinal) in names.iter().zip(ordinals) {
        let function = functions
            .get_mut(ordinal.get() as usize)
            .ok_or(malformed("export directory", "name ordinal out of range"))?;
        if (start..end).contains(&function.address.get()) {
            let forward = sections.rva_to_offset(function.address)?;
            function.forward_name = Some(bytes.ascii_string(forward.usize())?);
        }
        function.name = Some(bytes.ascii_string(sections.rva_to_offset(Rva(name.get()))?.usize())?);
    }
    Ok(functions)
}
