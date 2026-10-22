use crate::common::raw_structures::RAW_EXPORT_DIRECTORY;
use pers::Rva;
use pers::pe::ImageExportDirectory;

#[test]
fn image_export_directory_constructor_works_test() {
    let e = ImageExportDirectory::parse(RAW_EXPORT_DIRECTORY, 2).unwrap();

    assert_eq!(0x33221100, e.characteristics());
    assert_eq!(0x77665544, e.time_date_stamp());
    assert_eq!(0x9988, e.major_version());
    assert_eq!(0xbbaa, e.minor_version());
    assert_eq!(Rva(0xffeeddcc), e.name());
    assert_eq!(0x55443322, e.base());
    assert_eq!(0x44332211, e.number_of_functions());
    assert_eq!(0x88776655, e.number_of_names());
    assert_eq!(Rva(0xccbbaa99), e.address_of_functions());
    assert_eq!(Rva(0x00ffeedd), e.address_of_names());
    assert_eq!(Rva(0x55443322), e.address_of_name_ordinals());
}
