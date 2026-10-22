use crate::common::raw_structures::RAW_RESOURCE_DIRECTORY;
use pers::pe::ResourceDirectory;

#[test]
fn image_resource_directory_constructor_works_test() {
    let d = ResourceDirectory::parse(RAW_RESOURCE_DIRECTORY, 2, 2, RAW_RESOURCE_DIRECTORY.len())
        .unwrap();

    assert_eq!(0x33221100, d.header.characteristics());
    assert_eq!(0x77665544, d.header.time_date_stamp());
    assert_eq!(0x9988, d.header.major_version());
    assert_eq!(0xbbaa, d.header.minor_version());
    assert_eq!(0x0001, d.header.number_of_name_entries());
    assert_eq!(0x0001, d.header.number_of_id_entries());
    assert_eq!(0x44332211, d.entries[0].raw.name());
    assert_eq!(0x00000011, d.entries[0].raw.offset_to_data());
    assert_eq!(Some(0x44332222 & 0xFFFF), d.entries[1].id());
    assert_eq!(0x00000022, d.entries[1].raw.offset_to_data());
}
