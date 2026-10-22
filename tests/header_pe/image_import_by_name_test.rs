use crate::common::raw_structures::RAW_IMPORT_BY_NAME;
use pers::pe::ImageImportByName;

#[test]
fn image_import_by_name_constructor_works_test() {
    let import_by_name = ImageImportByName::parse(RAW_IMPORT_BY_NAME, 2).unwrap();
    assert_eq!(0x1100, import_by_name.hint);
    assert_eq!("Hello World", import_by_name.name);
}
