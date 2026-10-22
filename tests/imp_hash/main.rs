#[path = "../common/mod.rs"]
mod common;

use common::load;
use pers::PeFile;

#[test]
fn imp_hash_given_a_binary_computes_correct_hash() {
    let cases = [
        ("win_test.dll", "f9f97e60cfcd78be051d9570c88ffb6f"),
        ("NetCoreConsole.dll", "f34d5f2d4577ed6d9ceec516c1f5a744"),
        ("pidgin.exe", "91f96ce80cb6ee2b5e5fb6cc19bac72b"),
    ];
    for (file, expected) in cases {
        let data = load(file);
        let imp_hash = PeFile::parse(&data).unwrap().imp_hash().unwrap().unwrap();
        assert_eq!(expected, hex::encode(imp_hash), "{file}");
    }
}
