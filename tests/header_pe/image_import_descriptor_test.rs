use crate::common::raw_structures::RAW_IMPORT_DESCRIPTOR;
use pers::Rva;
use pers::pe::ImageImportDescriptor;

#[test]
fn image_import_descriptor_constructor_works_test() {
    let d = ImageImportDescriptor::parse(RAW_IMPORT_DESCRIPTOR, 2).unwrap();
    assert_eq!(Rva(0x33221100), d.original_first_thunk());
    assert_eq!(0x77665544, d.time_date_stamp());
    assert_eq!(0xbbaa9988, d.forwarder_chain());
    assert_eq!(Rva(0xffeeddcc), d.name());
    assert_eq!(Rva(0x44332211), d.first_thunk());
}
