use crate::common::raw_structures::RAW_COPYRIGHT;
use pers::pe::Copyright;

#[test]
fn copyright_constructor_works_test() {
    let copyright = Copyright::parse(RAW_COPYRIGHT, 2).unwrap();
    assert_eq!("copyright", copyright.copyright_string);
}
