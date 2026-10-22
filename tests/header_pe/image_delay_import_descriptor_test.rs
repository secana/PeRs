use crate::common::raw_structures::RAW_DELAY_IMPORT_DESCRIPTOR;
use pers::Rva;
use pers::pe::ImageDelayImportDescriptor;

#[test]
fn image_delay_import_descriptor_constructor_works_test() {
    let d = ImageDelayImportDescriptor::parse(RAW_DELAY_IMPORT_DESCRIPTOR, 0x2).unwrap();
    assert_eq!(0x33221100, d.attributes());
    assert_eq!(Rva(0x77665544), d.name());
    assert_eq!(Rva(0xbbaa9988), d.module_handle());
    assert_eq!(Rva(0xffeeddcc), d.import_address_table());
    assert_eq!(Rva(0x44332211), d.import_name_table());
    assert_eq!(Rva(0xccbbaa99), d.unload_information_table());
    assert_eq!(0x00ffeedd, d.time_date_stamp());
}
