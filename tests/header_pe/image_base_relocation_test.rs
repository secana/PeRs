use crate::common::raw_structures::RAW_IMAGE_BASE_RELOCATION;
use pers::Rva;
use pers::pe::ImageBaseRelocation;

#[test]
fn size_of_block_is_bigger_than_reloc_dir_size_test() {
    let raw_image_base_reloc_broken = [
        0x00, 0x00, 0x01, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x30, 0xC4, 0x30,
    ];
    assert!(ImageBaseRelocation::parse(&raw_image_base_reloc_broken, 0, 0).is_err());
}

#[test]
fn offset_is_bigger_than_buffer_test() {
    assert!(ImageBaseRelocation::parse(RAW_IMAGE_BASE_RELOCATION, 1234, 12).is_err());
}

#[test]
fn image_base_relocation_constructor_works_test() {
    let ibr = ImageBaseRelocation::parse(RAW_IMAGE_BASE_RELOCATION, 2, 12).unwrap();
    let entries: Vec<_> = ibr.entries().collect();

    assert_eq!(Rva(0x10000), ibr.virtual_address);
    assert_eq!(0xc, ibr.size_of_block);
    assert_eq!(2, entries.len());
    assert_eq!((0x2211u16 >> 12) as u8, entries[0].relocation_type());
    assert_eq!(0x2211 & 0xfff, entries[0].page_offset());
    assert_eq!((0x4433u16 >> 12) as u8, entries[1].relocation_type());
    assert_eq!(0x4433 & 0xfff, entries[1].page_offset());
}
