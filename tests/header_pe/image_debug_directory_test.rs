use uuid::Uuid;

use crate::common::load;
use crate::common::raw_structures::RAW_DEBUG_DIRECTORY;
use pers::pe::{DebugDirectoryType, ExtendedDllCharacteristics, ImageDebugDirectory};
use pers::{FileOffset, PeFile, Rva};

#[test]
fn image_debug_directory_constructor_works_test() {
    let idd = ImageDebugDirectory::parse(RAW_DEBUG_DIRECTORY, 2).unwrap();

    assert_eq!(0x44332211, idd.characteristics());
    assert_eq!(0x88776655, idd.time_date_stamp());
    assert_eq!(0xaa99, idd.major_version());
    assert_eq!(0xccbb, idd.minor_version());
    assert_eq!(0x11ffeedd, idd.debug_type().value());
    assert_eq!(0x55443322, idd.size_of_data());
    assert_eq!(Rva(0x99887766), idd.address_of_raw_data());
    assert_eq!(FileOffset(0xddccbbaa), idd.pointer_to_raw_data());
}

#[test]
fn parse_debug_directory_multiple_entries_returns_all_entries() {
    let data = load("TLSCallback_x64.dll");
    let pe_file = PeFile::parse(&data).unwrap();
    let debug_entries = pe_file.debug_directory().unwrap().unwrap();

    assert_eq!(4, debug_entries.len());
    assert_eq!(Rva(0x000023B0), debug_entries[0].address_of_raw_data());
    assert_eq!(Rva(0x0000241C), debug_entries[1].address_of_raw_data());
    assert_eq!(Rva(0x00002430), debug_entries[2].address_of_raw_data());
    assert_eq!(Rva(0x00000000), debug_entries[3].address_of_raw_data());

    assert_eq!(DebugDirectoryType::CodeView, debug_entries[0].debug_type());
    assert_eq!(DebugDirectoryType::VcFeature, debug_entries[1].debug_type());
    assert_eq!(DebugDirectoryType::Pogo, debug_entries[2].debug_type());
    assert_eq!(DebugDirectoryType::Iltcg, debug_entries[3].debug_type());
}

#[test]
fn parse_debug_directory_multiple_entries_extended_dll_characteristics() {
    let data = load("TestCetCompatAndEhCont.exe");
    let pe_file = PeFile::parse(&data).unwrap();
    let debug_entries = pe_file.debug_directory().unwrap().unwrap();

    assert_eq!(5, debug_entries.len());
    assert_eq!(DebugDirectoryType::CodeView, debug_entries[0].debug_type());
    assert_eq!(DebugDirectoryType::VcFeature, debug_entries[1].debug_type());
    assert_eq!(DebugDirectoryType::Pogo, debug_entries[2].debug_type());
    assert_eq!(DebugDirectoryType::Iltcg, debug_entries[3].debug_type());
    assert_eq!(
        DebugDirectoryType::ExtendedDllCharacteristics,
        debug_entries[4].debug_type()
    );
    assert_eq!(
        Some(ExtendedDllCharacteristics::CET_COMPAT),
        debug_entries[4]
            .extended_dll_characteristics(&data)
            .unwrap()
    );
}

fn assert_cv_info(file: &str, signature: &str, age: u32, pdb_file_name: &str) {
    let data = load(file);
    let pe_file = PeFile::parse(&data).unwrap();
    let entry = pe_file.debug_directory().unwrap().unwrap()[0];
    let cv = entry.cv_info_pdb70(&data).unwrap().unwrap();

    assert_eq!(0x53445352, cv.cv_signature);
    assert_eq!(Uuid::parse_str(signature).unwrap(), cv.signature);
    assert_eq!(age, cv.age);
    assert_eq!(pdb_file_name, cv.pdb_file_name);
}

#[test]
fn image_debug_directory_pe_file_with_debug_info1_parse_cv_header() {
    assert_cv_info(
        "pdb_guid.exe",
        "0de6dc23-8e19-4bb7-8608-d54b1e6fa379",
        1,
        "ntkrnlmp.pdb",
    );
}

#[test]
fn image_debug_directory_pe_file_with_debug_info2_parse_cv_header() {
    assert_cv_info(
        "firefox_x86_2.exe",
        "37bca9fb-2576-469b-8575-0a210e895e31",
        2,
        r"z:\build\build\src\obj-firefox\browser\app\firefox.pdb",
    );
}
