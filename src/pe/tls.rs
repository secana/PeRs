use zerocopy::little_endian::U32;

use crate::bytes::Bytes;
use crate::error::Result;

pe_layouts! {
    for TlsDirectory<'_>;
    /// The IMAGE_TLS_DIRECTORY32.
    pub struct ImageTlsDirectory32;
    /// The IMAGE_TLS_DIRECTORY64.
    pub struct ImageTlsDirectory64;
    fields {
            ptr start_address_of_raw_data,
            ptr end_address_of_raw_data,
            ptr address_of_index,
            ptr address_of_call_backs,
            fixed size_of_zero_fill: U32 => u32,
            fixed characteristics: U32 => u32,
    }
}

/// The TLS directory of a 32 or 64 bit file. Addresses are virtual addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsDirectory<'a> {
    Pe32(&'a ImageTlsDirectory32),
    Pe64(&'a ImageTlsDirectory64),
}

impl<'a> TlsDirectory<'a> {
    pub fn parse(data: &'a [u8], offset: usize, is_64_bit: bool) -> Result<Self> {
        let bytes = Bytes(data);
        if is_64_bit {
            bytes.read(offset).map(Self::Pe64)
        } else {
            bytes.read(offset).map(Self::Pe32)
        }
    }
}
