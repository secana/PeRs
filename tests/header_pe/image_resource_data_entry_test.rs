use crate::common::raw_structures::RAW_RESOURCE_DATA_ENTRY;
use pers::Rva;
use pers::pe::ImageResourceDataEntry;

#[test]
fn image_resource_data_entry_constructor_works_test() {
    let e = ImageResourceDataEntry::parse(RAW_RESOURCE_DATA_ENTRY, 2).unwrap();

    assert_eq!(Rva(0x33221100), e.offset_to_data());
    assert_eq!(0x77665544, e.size());
    assert_eq!(0xbbaa9988, e.code_page());
    assert_eq!(0xffeeddcc, e.reserved());
}
