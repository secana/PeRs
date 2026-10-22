use crate::common::raw_structures::{
    RAW_RESOURCE_DIRECTORY_ENTRY_BY_ID, RAW_RESOURCE_DIRECTORY_ENTRY_BY_NAME,
};
use pers::pe::ImageResourceDirectoryEntry;

#[test]
fn resource_directory_entry_by_name_constructor_works_test() {
    let e = ImageResourceDirectoryEntry::parse(RAW_RESOURCE_DIRECTORY_ENTRY_BY_NAME, 2).unwrap();

    assert!(e.is_named_entry());
    assert!(!e.is_id_entry());
    assert_eq!(0x80332211, e.name());
    assert_eq!(0x55443322, e.offset_to_data());
}

#[test]
fn resource_directory_entry_by_id_constructor_works_test() {
    let e = ImageResourceDirectoryEntry::parse(RAW_RESOURCE_DIRECTORY_ENTRY_BY_ID, 2).unwrap();

    assert!(e.is_id_entry());
    assert!(!e.is_named_entry());
    assert_eq!(0x00332211 & 0xFFFF, e.id());
    assert_eq!(0x55443322, e.offset_to_data());
}
