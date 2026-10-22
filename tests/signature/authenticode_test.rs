use crate::common::{binary, load, test_file};
use pers::authenticode::asn1::{TAG_SEQUENCE, Tlv};
use pers::pe::DataDirectoryType;
use pers::{MmFile, PeFile, Rva};

fn assert_security_directory(pe_file: &PeFile, virtual_address: u32, size: u32) {
    let dd = pe_file.data_directory(DataDirectoryType::Security);
    assert_eq!(Rva(virtual_address), dd.virtual_address());
    assert_eq!(size, dd.size());
}

#[test]
fn get_authenticode_info_b_certificate_out_of_range_with_buffer() {
    let data = load("DRWUI.exe");
    let pe_file = PeFile::parse(&data).unwrap();

    assert_security_directory(&pe_file, 0x82C200, 0x1428);
    assert!(!pe_file.is_signed());
    assert!(pe_file.authenticode_info().is_err());
}

#[test]
fn get_authenticode_info_from_dotnet_x64_binary_with_buffer() {
    let data = load("dotnet_x64.dll");
    let pe_file = PeFile::parse(&data).unwrap();

    assert_security_directory(&pe_file, 0x00122C00, 0x00002450);
    assert!(pe_file.signing_certificate().unwrap().is_some());
    assert!(pe_file.authenticode_info().unwrap().is_some());
}

fn assert_unsigned(data: &[u8]) {
    let pe_file = PeFile::parse(data).unwrap();
    assert_security_directory(&pe_file, 0, 0);
    assert!(pe_file.signing_certificate().unwrap().is_none());
    assert!(pe_file.authenticode_info().unwrap().is_none());
}

#[test]
fn get_authenticode_info_from_arm_dot_net_binary_with_buffer() {
    assert_unsigned(&load("arm_dotnet_binary.dll"));
}

#[test]
fn get_authenticode_info_from_arm_dot_net_binary_with_mmf() {
    assert_unsigned(&MmFile::open_read_only(binary("arm_dotnet_binary.dll")).unwrap());
}

#[test]
fn get_authenticode_info_from_arm_binary_with_buffer() {
    assert_unsigned(&load("arm_binary.dll"));
}

#[test]
fn get_authenticode_info_from_arm_binary_with_mmf() {
    assert_unsigned(&MmFile::open_read_only(binary("arm_binary.dll")).unwrap());
}

fn assert_signed_but_invalid(file: &str) {
    let data = load(file);
    let pe_file = PeFile::parse(&data).unwrap();
    assert!(pe_file.is_signed(), "{file}");
    assert!(!pe_file.has_valid_signature(), "{file}");
}

#[test]
fn is_signature_valid_manipulated_signature_x64_returns_false() {
    assert_signed_but_invalid("firefox_x64_manipulated.exe");
}

/// Firefox is signed by a broken certificate: the counter signature has no DigestInfo.
/// The Windows CAPI shows it's valid, but its not! https://github.com/dotnet/corefx/issues/34202
#[test]
fn is_signature_valid_signed_binary_old_x86_returns_false() {
    assert_signed_but_invalid("old_firefox_x86.exe");
}

/// See `is_signature_valid_signed_binary_old_x86_returns_false`.
#[test]
fn is_signature_valid_signed_binary_x86_returns_false() {
    assert_signed_but_invalid("firefox_x86.exe");
}

#[test]
fn is_signature_valid_invalid_signed_binary_x86_returns_false() {
    assert_signed_but_invalid("firefox_invalid_x86.exe");
}

#[test]
fn is_signature_valid_invalid_signed_binary_x64_returns_false() {
    assert_signed_but_invalid("firefox_invalid_x64.exe");
}

/// See `is_signature_valid_signed_binary_old_x86_returns_false`.
#[test]
fn is_signature_valid_signed_binary_x64_returns_false() {
    assert_signed_but_invalid("firefox_x64.exe");
}

#[test]
fn is_signature_valid_signed_binary_x86_other_returns_true() {
    let data = load("pidgin.exe");
    let pe_file = PeFile::parse(&data).unwrap();
    assert!(pe_file.is_signed());
    assert!(pe_file.has_valid_signature());
}

#[test]
fn signing_timestamp_signed_binary_returns_timestamp() {
    let data = load("pidgin.exe");
    let info = PeFile::parse(&data)
        .unwrap()
        .authenticode_info()
        .unwrap()
        .cloned()
        .unwrap();
    assert!(info.signing_timestamp.is_some());
}

#[test]
fn signing_timestamp_unsigned_binary_returns_null() {
    let data = load("TLSCallback_x86.exe");
    assert!(
        PeFile::parse(&data)
            .unwrap()
            .authenticode_info()
            .unwrap()
            .is_none()
    );
}

#[test]
fn signing_timestamp_legacy_counter_signature_returns_timestamp() {
    let data = load("old_firefox_x86.exe");
    let info = PeFile::parse(&data)
        .unwrap()
        .authenticode_info()
        .unwrap()
        .cloned()
        .unwrap();
    assert!(info.signing_timestamp.is_some());
}

#[test]
fn is_signature_valid_unsigned_binary_returns_false() {
    let data = load("TLSCallback_x86.exe");
    assert!(!PeFile::parse(&data).unwrap().has_valid_signature());
}

#[test]
fn prevent_overflow() {
    let cert = std::fs::read(test_file("Authenticode/pkcs7.bin")).unwrap();
    assert!(Tlv::parse_tagged(&cert, TAG_SEQUENCE).is_ok());
}

#[test]
fn asn1_should_support_ia5_string() {
    let cert = std::fs::read(test_file("Authenticode/pidgin.pkcs7")).unwrap();
    assert!(Tlv::parse_tagged(&cert, TAG_SEQUENCE).is_ok());
}
