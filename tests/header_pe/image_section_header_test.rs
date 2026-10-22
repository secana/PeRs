use crate::common::load;
use crate::common::raw_structures::RAW_SECTION_HEADER;
use pers::pe::{ImageSectionHeader, SectionCharacteristics};
use pers::{FileOffset, PeFile, Rva};

#[test]
fn image_section_header_constructor_works_test() {
    let section_header = ImageSectionHeader::parse(RAW_SECTION_HEADER, 2).unwrap();

    assert_eq!(".data", section_header.name());
    assert_eq!(0x33221100, section_header.virtual_size());
    assert_eq!(Rva(0x77665544), section_header.virtual_address());
    assert_eq!(0xbbaa9988, section_header.size_of_raw_data());
    assert_eq!(FileOffset(0xffeeddcc), section_header.pointer_to_raw_data());
    assert_eq!(0x44332211, section_header.pointer_to_relocations());
    assert_eq!(0x88776655, section_header.pointer_to_linenumbers());
    assert_eq!(0xaa99, section_header.number_of_relocations());
    assert_eq!(0xccbb, section_header.number_of_linenumbers());
    let characteristics = section_header.characteristics();
    assert_eq!(0x00000820, characteristics.bits());
    let names: Vec<_> = characteristics.iter_names().map(|(name, _)| name).collect();
    assert_eq!(vec!["CNT_CODE", "LNK_REMOVE"], names);
    assert!(
        characteristics
            .contains(SectionCharacteristics::LNK_REMOVE | SectionCharacteristics::CNT_CODE)
    );
}

#[test]
fn section_characteristics_alignment() {
    assert_eq!(
        None,
        SectionCharacteristics::from_bits_retain(0x20).alignment()
    );
    assert_eq!(
        Some(1),
        SectionCharacteristics::from_bits_retain(0x0010_0000).alignment()
    );
    assert_eq!(
        Some(16),
        SectionCharacteristics::from_bits_retain(0x0050_0000).alignment()
    );
    assert_eq!(
        Some(8192),
        SectionCharacteristics::from_bits_retain(0x00E0_0000).alignment()
    );
}

#[test]
fn image_section_header_correct_section_names() {
    let data = load("pdb_guid.exe");
    let pe_file = PeFile::parse(&data).unwrap();
    let snc = pe_file.section_headers().unwrap();

    let expected = [
        ".text", "ERRATA", "INITKDBG", "POOLCODE", ".rdata", ".data", ".pdata", "ALMOSTRO",
        "CACHEALI", "PAGELK", "PAGE", "PAGEKD", "PAGEVRFY", "PAGEHDLS", "PAGEBGFX", "PAGEVRFB",
        ".edata", "PAGEDATA", "PAGEVRFD", "INITDATA", "INIT", ".rsrc", ".reloc",
    ];
    let names: Vec<_> = snc.iter().map(|s| s.name().into_owned()).collect();
    assert_eq!(expected.as_slice(), names.as_slice());
}
