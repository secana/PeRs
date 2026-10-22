use crate::common::load;
use crate::common::raw_structures::{
    RAW_IMAGE_OPTIONAL_HEADER32_BIT, RAW_IMAGE_OPTIONAL_HEADER64_BIT,
};
use pers::pe::{
    DataDirectoryType, DllCharacteristics, ImageDataDirectory, MagicType, OptionalHeader,
    SubsystemType,
};
use pers::{PeFile, Rva};

fn parse(data: &[u8], is_64_bit: bool) -> (OptionalHeader<'_>, &[ImageDataDirectory]) {
    let header = OptionalHeader::parse_as(data, 2, is_64_bit).unwrap();
    let directories = ImageDataDirectory::parse_table(data, 2 + header.size()).unwrap();
    (header, directories)
}

#[test]
fn optional_header_constructor64_bit_works_test() {
    let (opt_header, directories) = parse(RAW_IMAGE_OPTIONAL_HEADER64_BIT, true);

    assert_common_opt_header_properties(&opt_header);
    assert_eq!(None, opt_header.base_of_data());
    assert_eq!(0x00112233aa99cc44, opt_header.image_base());
    assert_eq!(0x55443322aa99ddff, opt_header.size_of_stack_reserve());
    assert_eq!(0xaa998888aa998888, opt_header.size_of_stack_commit());
    assert_eq!(0xaa99cceeaa99ccee, opt_header.size_of_heap_reserve());
    assert_eq!(0xaa991177aa991177, opt_header.size_of_heap_commit());

    assert_data_directories(directories);
}

#[test]
fn optional_header_constructor32_bit_works_test() {
    let (opt_header, directories) = parse(RAW_IMAGE_OPTIONAL_HEADER32_BIT, false);

    assert_common_opt_header_properties(&opt_header);
    assert_eq!(Some(Rva(0xaa998844)), opt_header.base_of_data());
    assert_eq!(0xaa99cc44, opt_header.image_base());
    assert_eq!(0xaa99ddff, opt_header.size_of_stack_reserve());
    assert_eq!(0xaa998888, opt_header.size_of_stack_commit());
    assert_eq!(0xaa99ccee, opt_header.size_of_heap_reserve());
    assert_eq!(0xaa991177, opt_header.size_of_heap_commit());

    assert_data_directories(directories);
}

fn assert_common_opt_header_properties(opt_header: &OptionalHeader) {
    assert_eq!(MagicType::Bit32, opt_header.magic());
    assert_eq!(0x11, opt_header.major_linker_version());
    assert_eq!(0x33, opt_header.minor_linker_version());
    assert_eq!(0x22115544, opt_header.size_of_code());
    assert_eq!(0xaa998877, opt_header.size_of_initialized_data());
    assert_eq!(0x22115544, opt_header.size_of_uninitialized_data());
    assert_eq!(Rva(0xaa778822), opt_header.address_of_entry_point());
    assert_eq!(Rva(0xaaff8877), opt_header.base_of_code());
    assert_eq!(0xaa99cc77, opt_header.section_alignment());
    assert_eq!(0xaa99ffdd, opt_header.file_alignment());
    assert_eq!(0x8877, opt_header.major_operating_system_version());
    assert_eq!(0xaa99, opt_header.minor_operating_system_version());
    assert_eq!(0x44ff, opt_header.major_image_version());
    assert_eq!(0xeedd, opt_header.minor_image_version());
    assert_eq!(0x88bb, opt_header.major_subsystem_version());
    assert_eq!(0xaaee, opt_header.minor_subsystem_version());
    assert_eq!(0xaa998877, opt_header.win32_version_value());
    assert_eq!(0xaaff8877, opt_header.size_of_headers());
    assert_eq!(0xcc998877, opt_header.check_sum());
    assert_eq!(SubsystemType::WindowsCui, opt_header.subsystem());
    assert_eq!("Windows CUI", opt_header.subsystem().description());
    assert_eq!(0xaa99, opt_header.dll_characteristics().bits());
    assert_eq!(0xaa998822, opt_header.loader_flags());
    assert_eq!(0x00000005, opt_header.number_of_rva_and_sizes());
}

fn assert_data_directories(data_directories: &[ImageDataDirectory]) {
    use DataDirectoryType::*;

    assert_eq!(16, data_directories.len());

    let expected = [
        (Export, 0x44332211, 0x44332233),
        (Import, 0x44332244, 0x44332255),
        (Resource, 0x44887766, 0x4433aa99),
        (Exception, 0x44882211, 0x44334433),
        (Security, 0x443322bb, 0x443322cc),
        (BaseReloc, 0x443322dd, 0x443322ee),
        (Debug, 0x443322ff, 0x44333311),
        (Copyright, 0x44334411, 0x44335511),
        (GlobalPtr, 0x44336611, 0x44337711),
        (Tls, 0x44338811, 0x44339911),
        (LoadConfig, 0x4433aa11, 0x4433bb11),
        (BoundImport, 0x443399ee, 0x44330099),
        (Iat, 0x4433cc11, 0x4433dd11),
        (DelayImport, 0x4433ee11, 0x4433ff11),
        (ComDescriptor, 0x44442211, 0x44552211),
        (Reserved, 0xffcc2211, 0x44cc2211),
    ];
    for (dd, virtual_address, size) in expected {
        let directory = &data_directories[dd as usize];
        assert_eq!(Rva(virtual_address), directory.virtual_address(), "{dd:?}");
        assert_eq!(size, directory.size(), "{dd:?}");
    }
}

fn dll_characteristics(file: &str) -> DllCharacteristics {
    let data = load(file);
    PeFile::parse(&data)
        .unwrap()
        .nt_headers()
        .optional_header
        .dll_characteristics()
}

#[test]
fn dll_characteristics_missing_no_seh_flag() {
    let characteristics = dll_characteristics("firefox_x64.exe");

    assert_eq!(0xC160, characteristics.bits());
    assert!(!characteristics.contains(DllCharacteristics::NO_SEH));
}

#[test]
fn dll_characteristics_set_no_seh_flag() {
    let characteristics = dll_characteristics("No_SEH.exe");

    assert_eq!(0x08540, characteristics.bits());
    assert!(characteristics.contains(DllCharacteristics::NO_SEH));
}
