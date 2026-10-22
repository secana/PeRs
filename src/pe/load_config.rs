use zerocopy::little_endian::{U16, U32, U64};

use crate::bytes::Bytes;
use crate::error::Result;

pe_struct! {
    pub struct ImageLoadConfigCodeIntegrity {
        flags: U16 => u16,
        catalog: U16 => u16,
        catalog_offset: U32 => u32,
        reserved: U32 => u32,
    }
}

pe_layouts! {
    for LoadConfigDirectory;
    /// The complete IMAGE_LOAD_CONFIG_DIRECTORY32.
    pub struct ImageLoadConfigDirectory32;
    /// The complete IMAGE_LOAD_CONFIG_DIRECTORY64.
    pub struct ImageLoadConfigDirectory64;
    fields {
            fixed size: U32 => u32,
            fixed time_date_stamp: U32 => u32,
            fixed major_version: U16 => u16,
            fixed minor_version: U16 => u16,
            fixed global_flags_clear: U32 => u32,
            fixed global_flags_set: U32 => u32,
            fixed critical_section_default_timeout: U32 => u32,
            ptr de_commit_free_block_threshold,
            ptr de_commit_total_free_threshold,
            ptr lock_prefix_table,
            ptr maximum_allocation_size,
            ptr virtual_memory_threshold,
            pe64 process_affinity_mask: U64 => u64,
            fixed process_heap_flags: U32 => u32,
            pe32 process_affinity_mask: U32 => u32,
            fixed csd_version: U16 => u16,
            fixed dependent_load_flags: U16 => u16,
            ptr edit_list,
            ptr security_cookie,
            ptr se_handler_table,
            ptr se_handler_count,
            ptr guard_cf_check_function_pointer,
            ptr guard_cf_dispatch_function_pointer,
            ptr guard_cf_function_table,
            ptr guard_cf_function_count,
            fixed guard_flags: U32 => u32,
            fixed code_integrity: ImageLoadConfigCodeIntegrity => ImageLoadConfigCodeIntegrity,
            ptr guard_address_taken_iat_entry_table,
            ptr guard_address_taken_iat_entry_count,
            ptr guard_long_jump_target_table,
            ptr guard_long_jump_target_count,
            ptr dynamic_value_reloc_table,
            ptr chpe_metadata_pointer,
            ptr guard_rf_failure_routine,
            ptr guard_rf_failure_routine_function_pointer,
            fixed dynamic_value_reloc_table_offset: U32 => u32,
            fixed dynamic_value_reloc_table_section: U16 => u16,
            fixed reserved2: U16 => u16,
            ptr guard_rf_verify_stack_pointer_function_pointer,
            fixed hot_patch_table_offset: U32 => u32,
            fixed reserved3: U32 => u32,
            ptr enclave_configuration_pointer,
            ptr volatile_metadata_pointer,
            ptr guard_eh_continuation_table,
            ptr guard_eh_continuation_count,
            ptr guard_xfg_check_function_pointer,
            ptr guard_xfg_dispatch_function_pointer,
            ptr guard_xfg_table_dispatch_function_pointer,
            ptr cast_guard_os_determined_failure_mode,
            ptr guard_memcpy_function_pointer,
    }
}

/// The load config directory of a 32 or 64 bit file. The structure is copied, because files
/// often contain a shorter, older version of it: fields after the stored `size` (or the end of
/// the data) are 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadConfigDirectory {
    Pe32(ImageLoadConfigDirectory32),
    Pe64(ImageLoadConfigDirectory64),
}

impl LoadConfigDirectory {
    pub fn parse(data: &[u8], offset: usize, is_64_bit: bool) -> Result<Self> {
        let bytes = Bytes(data);
        let size = (bytes.u32(offset)? as usize).min(bytes.len() - offset);
        let available = bytes.slice(offset, size)?;
        Ok(if is_64_bit {
            Self::Pe64(copy_padded(available))
        } else {
            Self::Pe32(copy_padded(available))
        })
    }

    forward!(
        process_affinity_mask -> u64,
    );
}

/// Copy `bytes` into a zeroed structure.
fn copy_padded<T: zerocopy::FromBytes + zerocopy::IntoBytes + Copy>(bytes: &[u8]) -> T {
    let mut value = T::new_zeroed();
    let target = value.as_mut_bytes();
    let length = bytes.len().min(target.len());
    target[..length].copy_from_slice(&bytes[..length]);
    value
}
