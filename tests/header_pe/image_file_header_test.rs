use crate::common::raw_structures::RAW_FILE_HEADER;
use pers::pe::{FileCharacteristics, ImageFileHeader, MachineType};

#[test]
fn image_file_header_constructor_works_test() {
    let file_header = ImageFileHeader::parse(RAW_FILE_HEADER, 2).unwrap();
    assert_eq!(MachineType::Amd64, file_header.machine());
    assert_eq!("AMD64", file_header.machine().description());
    assert_eq!(0x3322, file_header.number_of_sections());
    assert_eq!(0x77665544, file_header.time_date_stamp());
    assert_eq!(0xbbaa9988, file_header.pointer_to_symbol_table());
    assert_eq!(0xffeeddcc, file_header.number_of_symbols());
    assert_eq!(0x2211, file_header.size_of_optional_header());
    assert!(
        file_header
            .characteristics()
            .contains(FileCharacteristics::DLL)
    );
    assert!(
        file_header
            .characteristics()
            .iter_names()
            .any(|(name, _)| name == "DLL")
    );
}
