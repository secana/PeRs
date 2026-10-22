use crate::common::raw_structures::RAW_RESOURCE_DIR_STRING_U;
use pers::pe::ImageResourceDirStringU;

#[test]
fn image_resource_dir_string_u_constructor_works_test() {
    let first = ImageResourceDirStringU::parse(RAW_RESOURCE_DIR_STRING_U, 2).unwrap();
    assert_eq!(0x000b, first.length);
    assert_eq!("Hello World", first.name_string);

    // start offset + size of first length + length of first in bytes
    let second =
        ImageResourceDirStringU::parse(RAW_RESOURCE_DIR_STRING_U, 2 + 2 + 0x000b * 2).unwrap();
    assert_eq!(0x0006, second.length);
    assert_eq!("Second", second.name_string);
}
