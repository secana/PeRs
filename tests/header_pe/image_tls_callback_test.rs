use crate::common::load;
use pers::{PeFile, Va};

fn tls_callbacks(file: &str) -> Vec<Va> {
    let data = load(file);
    PeFile::parse(&data)
        .unwrap()
        .tls_callbacks()
        .unwrap()
        .unwrap()
}

#[test]
fn tls_callback_x86_works_test() {
    assert_eq!(vec![Va(0x004111CC)], tls_callbacks("TLSCallback_x86.exe"));
}

#[test]
fn tls_callback_x64_works1_test() {
    assert_eq!(
        vec![Va(0x0000000180001000)],
        tls_callbacks("TLSCallback_x64.dll")
    );
}

#[test]
fn tls_callback_x64_works2_test() {
    assert_eq!(
        vec![Va(0x00000001400044a0)],
        tls_callbacks("firefox_x64.exe")
    );
}
