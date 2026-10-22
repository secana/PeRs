#[path = "../common/mod.rs"]
mod common;

use std::path::PathBuf;

use common::binary;
use pers::MmFile;

fn copy_of_test_file(name: &str) -> PathBuf {
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::copy(binary("mmf_test.bin"), &target).unwrap();
    target
}

#[test]
fn length_returns_correct_length() {
    let mmf = MmFile::open_read_only(binary("firefox_x86.exe")).unwrap();

    assert_eq!(411_088, mmf.len());
}

#[test]
fn as_span_returns_span() {
    let mmf = MmFile::open_read_only(binary("mmf_test.bin")).unwrap();

    assert_eq!([0x11, 0x22, 0x33], mmf[0x16..0x19]);
}

#[test]
fn to_array_returns_array() {
    let mmf = MmFile::open_read_only(binary("mmf_test.bin")).unwrap();

    assert_eq!(0x42, mmf.to_vec().len());
}

#[test]
fn write_bytes_writes_bytes() {
    let mut mmf = MmFile::open(copy_of_test_file("mmf_test_writebytes.bin")).unwrap();

    mmf.as_mut_slice().unwrap()[0x15..0x17].copy_from_slice(&[0xaf, 0xbf]);

    assert_eq!([0xaf, 0xbf], mmf[0x15..0x17]);
}

#[test]
fn write_to_read_only_mapping_fails() {
    let mut mmf = MmFile::open_read_only(binary("mmf_test.bin")).unwrap();

    assert!(mmf.as_mut_slice().is_err());
}
