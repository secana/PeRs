use alloc::borrow::Cow;
use alloc::vec::Vec;

use zerocopy::little_endian::{U16, U32};

use super::SectionTable;
use crate::address::Rva;
use crate::bytes::{Bytes, encode_ascii};
use crate::error::Result;

/// Module names longer than this are treated as corrupted and skipped.
const MAX_MODULE_NAME_LENGTH: usize = 256;

pe_struct! {
    /// An IMAGE_IMPORT_DESCRIPTOR: one imported module.
    pub struct ImageImportDescriptor {
        /// RVA of the import name table (INT).
        original_first_thunk: U32 => Rva,
        time_date_stamp: U32 => u32,
        forwarder_chain: U32 => u32,
        /// RVA of the module name.
        name: U32 => Rva,
        /// RVA of the import address table (IAT).
        first_thunk: U32 => Rva,
    }
}

impl ImageImportDescriptor {
    /// The descriptor ending the array: all fields except the time stamp are 0.
    pub fn is_terminator(&self) -> bool {
        self.original_first_thunk().get() == 0
            && self.forwarder_chain() == 0
            && self.name().get() == 0
            && self.first_thunk().get() == 0
    }
}

pe_struct! {
    /// An IMAGE_DELAYLOAD_DESCRIPTOR: one delay loaded module.
    pub struct ImageDelayImportDescriptor {
        attributes: U32 => u32,
        /// RVA of the module name.
        name: U32 => Rva,
        module_handle: U32 => Rva,
        import_address_table: U32 => Rva,
        /// RVA of the import name table.
        import_name_table: U32 => Rva,
        bound_import_address_table: U32 => Rva,
        unload_information_table: U32 => Rva,
        time_date_stamp: U32 => u32,
    }
}

impl ImageDelayImportDescriptor {
    /// The descriptor ending the array: all fields except the time stamp are 0.
    pub fn is_terminator(&self) -> bool {
        self.attributes() == 0
            && self.name().get() == 0
            && self.module_handle().get() == 0
            && self.import_address_table().get() == 0
            && self.import_name_table().get() == 0
            && self.bound_import_address_table().get() == 0
            && self.unload_information_table().get() == 0
    }
}

pe_struct! {
    /// An IMAGE_BOUND_IMPORT_DESCRIPTOR.
    pub struct ImageBoundImportDescriptor {
        time_date_stamp: U32 => u32,
        offset_module_name: U16 => u16,
        number_of_module_forwarder_refs: U16 => u16,
    }
}

/// Parse a descriptor array that ends with a terminator entry.
pub(crate) fn parse_descriptors<T>(
    data: &[u8],
    offset: usize,
    is_terminator: impl Fn(&T) -> bool,
) -> Result<Vec<&T>>
where
    T: zerocopy::FromBytes + zerocopy::KnownLayout + zerocopy::Immutable + zerocopy::Unaligned,
{
    let bytes = Bytes(data);
    let mut descriptors = Vec::new();
    for index in 0.. {
        let descriptor: &T = bytes.read(offset + index * size_of::<T>())?;
        if is_terminator(descriptor) {
            break;
        }
        descriptors.push(descriptor);
    }
    Ok(descriptors)
}

/// An IMAGE_THUNK_DATA entry of an import name or address table: an ordinal, the RVA of an
/// [`ImageImportByName`] or an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageThunkData {
    pub address_of_data: u64,
    pub is_64_bit: bool,
}

impl ImageThunkData {
    pub fn parse(data: &[u8], offset: usize, is_64_bit: bool) -> Result<Self> {
        Ok(Self {
            address_of_data: Bytes(data).pointer(offset, is_64_bit)?,
            is_64_bit,
        })
    }

    pub fn size(is_64_bit: bool) -> usize {
        if is_64_bit { 8 } else { 4 }
    }

    /// The ordinal for imports by ordinal (most significant bit set).
    pub fn ordinal(&self) -> Option<u16> {
        let (ordinal_bit, mask) = if self.is_64_bit {
            (1 << 63, 0x7FFF_FFFF_FFFF_FFFF)
        } else {
            (1 << 31, 0x7FFF_FFFF)
        };
        (self.address_of_data & ordinal_bit != 0).then_some((self.address_of_data & mask) as u16)
    }
}

/// An IMAGE_IMPORT_BY_NAME entry: hint and name of an imported function.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageImportByName<'a> {
    pub hint: u16,
    pub name: Cow<'a, str>,
}

impl<'a> ImageImportByName<'a> {
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        Ok(Self {
            hint: bytes.u16(offset)?,
            name: bytes.ascii_string(offset + 2)?,
        })
    }

    /// The encoded entry: hint, ASCII name and zero terminator.
    pub(crate) fn encode(hint: u16, name: &str) -> Vec<u8> {
        let mut raw = hint.to_le_bytes().to_vec();
        raw.extend(encode_ascii(name));
        raw.push(0);
        raw
    }
}

/// A function imported by the file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImportFunction<'a> {
    /// `None` for imports by ordinal.
    pub name: Option<Cow<'a, str>>,
    pub dll: Cow<'a, str>,
    /// The hint for imports by name, the ordinal for imports by ordinal.
    pub hint: u16,
    /// Offset of the thunk relative to the start of the IAT.
    pub iat_offset: u32,
}

/// The RVAs of an import or delay import descriptor needed to parse its functions.
pub(crate) struct ImportThunks {
    pub name: Rva,
    pub thunk_table: Rva,
    pub iat_base: Rva,
}

/// What parsing import or delay import functions needs from the file.
pub(crate) struct ImportContext<'s, 'a> {
    pub data: &'a [u8],
    pub sections: &'s SectionTable<'a>,
    /// Start of the address table the IAT offsets of the functions are relative to.
    pub iat: Rva,
    pub is_64_bit: bool,
}

impl<'a> ImportContext<'_, 'a> {
    pub(crate) fn parse_functions(
        &self,
        modules: impl Iterator<Item = ImportThunks>,
    ) -> Result<Vec<ImportFunction<'a>>> {
        let (data, sections, is_64_bit) = (self.data, self.sections, self.is_64_bit);
        let bytes = Bytes(data);
        let size_of_thunk = ImageThunkData::size(is_64_bit) as u32;
        let mut functions = Vec::new();
        for module in modules {
            let dll = bytes.ascii_string(sections.rva_to_offset(module.name)?.usize())?;
            if dll.len() > MAX_MODULE_NAME_LENGTH || module.thunk_table.get() == 0 {
                continue;
            }
            let thunk_table = sections.rva_to_offset(module.thunk_table)?.get();
            for round in 0u32.. {
                let step = round.wrapping_mul(size_of_thunk);
                let thunk = ImageThunkData::parse(
                    data,
                    thunk_table.wrapping_add(step) as usize,
                    is_64_bit,
                )?;
                if thunk.address_of_data == 0 {
                    break;
                }
                let iat_offset = module
                    .iat_base
                    .get()
                    .wrapping_add(step)
                    .wrapping_sub(self.iat.get());
                let (name, hint) = match thunk.ordinal() {
                    Some(ordinal) => (None, ordinal),
                    None => {
                        let offset = sections.rva_to_offset(Rva(thunk.address_of_data as u32))?;
                        let by_name = ImageImportByName::parse(data, offset.usize())?;
                        (Some(by_name.name), by_name.hint)
                    }
                };
                functions.push(ImportFunction {
                    name,
                    dll: dll.clone(),
                    hint,
                    iat_offset,
                });
            }
        }
        Ok(functions)
    }
}
