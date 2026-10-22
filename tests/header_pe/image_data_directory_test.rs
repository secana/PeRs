use crate::common::raw_structures::RAW_DATA_DIRECTORY;
use pers::Rva;
use pers::pe::ImageDataDirectory;

#[test]
fn image_data_directory_constructor_works_test() {
    let data_directory = ImageDataDirectory::parse(RAW_DATA_DIRECTORY, 2).unwrap();

    assert_eq!(Rva(0x44332211), data_directory.virtual_address());
    assert_eq!(0x88776655, data_directory.size());
}
