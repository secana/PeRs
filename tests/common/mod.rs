#![allow(dead_code)]

#[rustfmt::skip]
pub mod raw_dot_net_structures;
#[rustfmt::skip]
pub mod raw_structures;

use std::path::PathBuf;

/// Absolute path of a file relative to the `tests` directory, e.g. `Binaries/pidgin.exe`.
pub fn test_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(relative)
}

pub fn binary(name: &str) -> PathBuf {
    test_file(&format!("Binaries/{name}"))
}

/// The content of a test binary.
pub fn load(name: &str) -> Vec<u8> {
    std::fs::read(binary(name)).unwrap()
}
