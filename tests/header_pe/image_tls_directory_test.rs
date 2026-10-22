use crate::common::raw_structures::{RAW_TLS_DIRECTORY32, RAW_TLS_DIRECTORY64};
use pers::pe::TlsDirectory;

#[test]
fn image_tls_directory64_constructor_works_test() {
    let d = TlsDirectory::parse(RAW_TLS_DIRECTORY64, 2, true).unwrap();

    assert_eq!(0x7766554433221100, d.start_address_of_raw_data());
    assert_eq!(0xbbaa998877665544, d.end_address_of_raw_data());
    assert_eq!(0x221100ffeeddccbb, d.address_of_index());
    assert_eq!(0xaa99887766554433, d.address_of_call_backs());
    assert_eq!(0x44332211, d.size_of_zero_fill());
    assert_eq!(0x99887766, d.characteristics());
}

#[test]
fn image_tls_directory32_constructor_works_test() {
    let d = TlsDirectory::parse(RAW_TLS_DIRECTORY32, 2, false).unwrap();

    assert_eq!(0x33221100, d.start_address_of_raw_data());
    assert_eq!(0x77665544, d.end_address_of_raw_data());
    assert_eq!(0xeeddccbb, d.address_of_index());
    assert_eq!(0x66554433, d.address_of_call_backs());
    assert_eq!(0x44332211, d.size_of_zero_fill());
    assert_eq!(0x99887766, d.characteristics());
}
