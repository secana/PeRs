use crate::common::raw_structures::RAW_WIN_CERTIFICATE;
use pers::pe::WinCertificate;

#[test]
fn win_certificate_constructor_works_test() {
    let c = WinCertificate::parse(RAW_WIN_CERTIFICATE, 2).unwrap();
    assert_eq!(0x0000000b, c.dw_length);
    assert_eq!(0x5544, c.w_revision);
    assert_eq!(0x7766, c.w_certificate_type.value());
    assert_eq!(Some([0x11, 0x22, 0x33].as_slice()), c.b_certificate);
}
