use alloc::vec::Vec;

use zerocopy::little_endian::U32;

use super::SectionTable;
use crate::address::Rva;
use crate::bytes::Bytes;
use crate::error::Result;

pe_struct! {
    /// A RUNTIME_FUNCTION entry of the x64 exception directory.
    pub struct RuntimeFunction {
        function_start: U32 => Rva,
        function_end: U32 => Rva,
        /// RVA of the unwind information.
        unwind_info_address: U32 => Rva,
    }
}

impl RuntimeFunction {
    /// Resolve the unwind information. A set lowest bit marks chained information.
    pub fn unwind_info(&self, data: &[u8], sections: &SectionTable) -> Result<UnwindInfo> {
        let address = self.unwind_info_address().get();
        let address = if address & 0x1 == 0x1 {
            address & 0xFFFE
        } else {
            address
        };
        UnwindInfo::parse(data, sections.rva_to_offset(Rva(address))?.usize())
    }
}

/// The UNWIND_INFO structure referenced by a runtime function.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub unwind_codes: Vec<UnwindCode>,
    /// The exception handler or chained function entry after the unwind codes, `None` if it is
    /// outside of the data.
    pub exception_handler: Option<u32>,
}

impl UnwindInfo {
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let version_and_flags = bytes.u8(offset)?;
        let count_of_codes = bytes.u8(offset + 2)?;
        let frame = bytes.u8(offset + 3)?;
        let even_count_of_codes = (count_of_codes as usize).div_ceil(2) * 2;
        Ok(Self {
            version: version_and_flags & 0x1F,
            flags: version_and_flags >> 5,
            size_of_prolog: bytes.u8(offset + 1)?,
            count_of_codes,
            frame_register: frame >> 4,
            frame_offset: frame & 0xF,
            unwind_codes: parse_unwind_codes(data, offset + 4, count_of_codes)?,
            exception_handler: bytes.u32(offset + 4 + 2 * even_count_of_codes).ok(),
        })
    }
}

fn parse_unwind_codes(data: &[u8], offset: usize, count_of_codes: u8) -> Result<Vec<UnwindCode>> {
    let mut codes = Vec::new();
    let mut current = offset;
    let mut nodes = 0u32;
    while nodes < count_of_codes as u32 {
        let code = UnwindCode::parse(data, current)?;
        let additional_nodes = code.additional_nodes();
        current += 2 * (1 + additional_nodes as usize);
        nodes += 1 + additional_nodes;
        codes.push(code);
    }
    Ok(codes)
}

/// An UNWIND_CODE entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnwindCode {
    pub code_offset: u8,
    pub unwind_op: UnwindOpType,
    pub op_info: u8,
    /// The 2 bytes after the code, used as frame offset by some operations.
    pub frame_offset: Option<u16>,
}

impl UnwindCode {
    pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
        let bytes = Bytes(data);
        let op = bytes.u8(offset + 1)?;
        Ok(Self {
            code_offset: bytes.u8(offset)?,
            unwind_op: UnwindOpType::from(op >> 4),
            op_info: op & 0xF,
            frame_offset: bytes.u16(offset + 2).ok(),
        })
    }

    /// Number of 2 byte nodes the operation uses in addition to the code itself.
    fn additional_nodes(&self) -> u32 {
        match self.unwind_op {
            UnwindOpType::AllocLarge if self.op_info == 0 => 1,
            UnwindOpType::AllocLarge => 2,
            UnwindOpType::SaveNonvol | UnwindOpType::SaveXmm128 => 1,
            UnwindOpType::SaveNonvolFar | UnwindOpType::SaveXmm128Far => 2,
            _ => 0,
        }
    }
}

pe_enum! {
    pub enum UnwindOpType: u8 {
        PushNonvol = 0,
        AllocLarge = 1,
        AllocSmall = 2,
        SetFpreg = 3,
        SaveNonvol = 4,
        SaveNonvolFar = 5,
        SaveXmm128 = 8,
        SaveXmm128Far = 9,
        PushMachframe = 10,
    }
}
