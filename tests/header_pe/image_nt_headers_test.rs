use crate::common::raw_structures::raw_image_nt_headers64;
use pers::pe::NtHeaders;

#[test]
fn image_nt_headers_constructor_works_test() {
    let data = raw_image_nt_headers64();
    let nt_headers = NtHeaders::parse(&data, 2).unwrap();
    assert_eq!(0x33221100, nt_headers.signature);
}
