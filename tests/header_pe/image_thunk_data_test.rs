use crate::common::raw_structures::{RAW_THUNK_DATA32, RAW_THUNK_DATA64};
use pers::pe::ImageThunkData;

#[test]
fn image_thunk_data64_constructor_works_test() {
    let t = ImageThunkData::parse(RAW_THUNK_DATA64, 2, true).unwrap();

    assert_eq!(0x7766554433221100, t.address_of_data);
    assert_eq!(None, t.ordinal());
}

#[test]
fn image_thunk_data32_constructor_works_test() {
    let t = ImageThunkData::parse(RAW_THUNK_DATA32, 2, false).unwrap();

    assert_eq!(0x33221100, t.address_of_data);
    assert_eq!(None, t.ordinal());
}

#[test]
fn image_thunk_data_with_ordinal_bit_is_import_by_ordinal() {
    assert_eq!(
        Some(0x1234),
        ImageThunkData::parse(&[0x34, 0x12, 0x00, 0x80], 0, false)
            .unwrap()
            .ordinal()
    );
}
