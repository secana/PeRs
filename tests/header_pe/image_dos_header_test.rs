use crate::common::raw_structures::RAW_DOS_HEADER;
use pers::pe::ImageDosHeader;

#[test]
fn image_dos_header_constructor_works_test() {
    let idh = ImageDosHeader::parse(RAW_DOS_HEADER, 0).unwrap();
    assert_eq!(0x1100, idh.e_magic());
    assert_eq!(0x3322, idh.e_cblp());
    assert_eq!(0x5544, idh.e_cp());
    assert_eq!(0x7766, idh.e_crlc());
    assert_eq!(0x9988, idh.e_cparhdr());
    assert_eq!(0xbbaa, idh.e_minalloc());
    assert_eq!(0xddcc, idh.e_maxalloc());
    assert_eq!(0x00ff, idh.e_ss());
    assert_eq!(0x2211, idh.e_sp());
    assert_eq!(0x4433, idh.e_csum());
    assert_eq!(0x6655, idh.e_ip());
    assert_eq!(0x8877, idh.e_cs());
    assert_eq!(0xaa99, idh.e_lfarlc());
    assert_eq!(0xccbb, idh.e_ovno());
    assert_eq!([0xeedd, 0x00ff, 0x2211, 0x4433], idh.e_res());
    assert_eq!(0x6655, idh.e_oemid());
    assert_eq!(0x8877, idh.e_oeminfo());
    assert_eq!(
        [
            0xaa99, 0xccbb, 0xeedd, 0x11ff, 0x3322, 0x5544, 0x7766, 0x9988, 0xbbaa, 0xbbcc
        ],
        idh.e_res2()
    );
}
