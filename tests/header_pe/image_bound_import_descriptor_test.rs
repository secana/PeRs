use crate::common::raw_structures::RAW_BOUND_IMPORT_DESCRIPTOR;
use pers::pe::ImageBoundImportDescriptor;

#[test]
fn image_bound_import_descriptor_constructor_works_test() {
    let d = ImageBoundImportDescriptor::parse(RAW_BOUND_IMPORT_DESCRIPTOR, 2).unwrap();
    assert_eq!(0x33221100, d.time_date_stamp());
    assert_eq!(0x5544, d.offset_module_name());
    assert_eq!(0x7766, d.number_of_module_forwarder_refs());
}
