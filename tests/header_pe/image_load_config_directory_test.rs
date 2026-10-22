use crate::common::raw_structures::{
    RAW_IMAGE_LOAD_CONFIG_DIRECTORY32, RAW_IMAGE_LOAD_CONFIG_DIRECTORY64,
};
use pers::pe::LoadConfigDirectory;

#[test]
fn image_load_config_directory32_constructor_works_test() {
    let d = LoadConfigDirectory::parse(RAW_IMAGE_LOAD_CONFIG_DIRECTORY32, 2, false).unwrap();

    assert_eq!(0x33221100, d.size());
    assert_eq!(0x77665544, d.time_date_stamp());
    assert_eq!(0x9988, d.major_version());
    assert_eq!(0xbbaa, d.minor_version());
    assert_eq!(0xffeeddcc, d.global_flags_clear());
    assert_eq!(0x44332211, d.global_flags_set());
    assert_eq!(0x88776655, d.critical_section_default_timeout());
    assert_eq!(0xccbbaa99, d.de_commit_free_block_threshold());
    assert_eq!(0x00ffeedd, d.de_commit_total_free_threshold());
    assert_eq!(0x55443322, d.lock_prefix_table());
    assert_eq!(0x99887766, d.maximum_allocation_size());
    assert_eq!(0xddccbbaa, d.virtual_memory_threshold());
    assert_eq!(0x221100ff, d.process_heap_flags());
    assert_eq!(0x66554433, d.process_affinity_mask());
    assert_eq!(0x8877, d.csd_version());
    assert_eq!(0xaa99, d.dependent_load_flags());
    assert_eq!(0xffddccbb, d.edit_list());
    assert_eq!(0x77665544, d.security_cookie());
    assert_eq!(0xbbaa9988, d.se_handler_table());
    assert_eq!(0xffeeddcc, d.se_handler_count());
    assert_eq!(0x88776655, d.guard_cf_check_function_pointer());
    assert_eq!(0xccbbaa99, d.guard_cf_dispatch_function_pointer());
    assert_eq!(0x00ffeedd, d.guard_cf_function_table());
    assert_eq!(0x99887766, d.guard_cf_function_count());
    assert_eq!(0xddccbbaa, d.guard_flags());
}

#[test]
fn image_load_config_directory64_constructor_works_test() {
    let d = LoadConfigDirectory::parse(RAW_IMAGE_LOAD_CONFIG_DIRECTORY64, 2, true).unwrap();

    assert_eq!(0x33221100, d.size());
    assert_eq!(0x77665544, d.time_date_stamp());
    assert_eq!(0x9988, d.major_version());
    assert_eq!(0xbbaa, d.minor_version());
    assert_eq!(0xffeeddcc, d.global_flags_clear());
    assert_eq!(0x44332211, d.global_flags_set());
    assert_eq!(0x88776655, d.critical_section_default_timeout());
    assert_eq!(0xddccbbaaccbbaa99, d.de_commit_free_block_threshold());
    assert_eq!(0xddccbbaa00ffeedd, d.de_commit_total_free_threshold());
    assert_eq!(0xddccbbaa55443322, d.lock_prefix_table());
    assert_eq!(0xddccbbaa99887766, d.maximum_allocation_size());
    assert_eq!(0xddccbbaaddccbbaa, d.virtual_memory_threshold());
    assert_eq!(0xddccbbaa66554433, d.process_affinity_mask());
    assert_eq!(0x221100ff, d.process_heap_flags());
    assert_eq!(0x8877, d.csd_version());
    assert_eq!(0xaa99, d.dependent_load_flags());
    assert_eq!(0xddccbbaaffddccbb, d.edit_list());
    assert_eq!(0xddccbbaa77665544, d.security_cookie());
    assert_eq!(0xddccbbaabbaa9988, d.se_handler_table());
    assert_eq!(0xddccbbaaffeeddcc, d.se_handler_count());
    assert_eq!(0xddccbbaa88776655, d.guard_cf_check_function_pointer());
    assert_eq!(0xddccbbaaccbbaa99, d.guard_cf_dispatch_function_pointer());
    assert_eq!(0xddccbbaa00ffeedd, d.guard_cf_function_table());
    assert_eq!(0xddccbbaa99887766, d.guard_cf_function_count());
    assert_eq!(0xddccbbaa, d.guard_flags());
}

#[test]
fn image_load_config_directory_fields_after_the_data_are_zero() {
    let d = LoadConfigDirectory::parse(RAW_IMAGE_LOAD_CONFIG_DIRECTORY32, 2, false).unwrap();

    assert_eq!(0, d.guard_memcpy_function_pointer());
}
