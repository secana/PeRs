use crate::common::load;
use pers::PeFile;
use pers::authenticode::HashAlgorithm;

#[test]
fn authenticode_hash_given_a_binary_computes_correct_hash() {
    let cases = [
        ("add-import.exe", "68555fb55b4d974628d429eda7f5e282d647b426"),
        (
            "add-section.exe",
            "68555fb55b4d974628d429eda7f5e282d647b426",
        ),
        ("arm_binary.dll", "c722f439a2630f31b993917190c29604b8aad3b8"),
        (
            "arm_dotnet_binary.dll",
            "9bca7cc604e504475e46c2a2192a24c4c11abb43",
        ),
        ("chrome_elf.dll", "33ea37b6958a008549dc395e2932095f34bcbf8b"),
        ("dotnet_x64.dll", "3a482db1ed60fdab5fa7862b414797cad4f00524"),
        (
            "firefox_invalid_x64.exe",
            "79da1b80964d0ef4e661b74d09e4d01dfb71fa95",
        ),
        (
            "firefox_invalid_x86.exe",
            "90dfa709c0ad470a44a6155aa6af7b136318967b",
        ),
        (
            "firefox_x64_copy1.exe",
            "f9e7919f2e19cacc6af2cdd5919a31999c9d2fb6",
        ),
        (
            "firefox_x64_copy2.exe",
            "f9e7919f2e19cacc6af2cdd5919a31999c9d2fb6",
        ),
        (
            "firefox_x64_manipulated.exe",
            "6dece04e93fca237197f53d31b18bb3bda72b15d",
        ),
        (
            "firefox_x64.exe",
            "f9e7919f2e19cacc6af2cdd5919a31999c9d2fb6",
        ),
        (
            "firefox_x86_2.exe",
            "0b4ba5ddad3dedef928db97c674703f5bf3e5f81",
        ),
        (
            "firefox_x86.exe",
            "0b4ba5ddad3dedef928db97c674703f5bf3e5f81",
        ),
        ("krnl_test.sys", "b0020506b5b26ba8327d3dcce41ca134c633824b"),
        (
            "NetCoreConsole.dll",
            "61420d9b7cf60b37caab6918c4ce89ce5a029bfc",
        ),
        (
            "NetFrameworkConsole.exe",
            "5728a7e8d46bbccb3b46804678d32e89000cf97c",
        ),
        ("No_SEH.exe", "796ffb54e4df71bbba8802f514aefb609f6eb901"),
        (
            "old_firefox_x86.exe",
            "c8d6c881cdd701f8630ca25ed6624ace69010ca0",
        ),
        (
            "osx_vb_netcore.dll",
            "73297a8a0693b2024c4800d38fa67d1fae9fa2e1",
        ),
        ("pdb_guid.exe", "1deaa6bf0c338973d81742e0a4930be35348f813"),
        ("pidgin.exe", "5cf1e042d80711ec0bc3ce05be8c34a280e5f512"),
        (
            "remove-section.exe",
            "68555fb55b4d974628d429eda7f5e282d647b426",
        ),
        (
            "TLSCallback_x64.dll",
            "92e1156b6a0b77d863388ad0a08e766b91a11aeb",
        ),
        (
            "TLSCallback_x86.exe",
            "4546c11743b919ce740d40de71369493ae1dde46",
        ),
        ("win_test.dll", "314d1a82f923679d76446bcbeb557de2a390519c"),
    ];
    for (file, expected) in cases {
        let data = load(file);
        let pe_file = PeFile::parse(&data).unwrap();
        assert!(pe_file.authenticode_info().is_ok(), "{file}");

        assert_eq!(
            expected,
            hex::encode(pe_file.authenticode_hash(HashAlgorithm::Sha1).unwrap()),
            "{file}"
        );
    }
}

#[test]
fn authenticode_hash_sha256_matches_signed_hash() {
    let data = load("pidgin.exe");
    let pe_file = PeFile::parse(&data).unwrap();
    let signed_hash = pe_file
        .authenticode_info()
        .unwrap()
        .unwrap()
        .signed_hash
        .unwrap();

    assert_eq!(
        signed_hash,
        pe_file.authenticode_hash(HashAlgorithm::Sha256).unwrap()
    );
}

#[test]
fn authenticode_hash_given_algorithm_returns_digest_of_its_length() {
    let data = load("pidgin.exe");
    let pe_file = PeFile::parse(&data).unwrap();
    let cases = [
        (HashAlgorithm::Md5, 16),
        (HashAlgorithm::Sha1, 20),
        (HashAlgorithm::Sha256, 32),
        (HashAlgorithm::Sha384, 48),
        (HashAlgorithm::Sha512, 64),
    ];
    for (algorithm, length) in cases {
        assert_eq!(
            length,
            pe_file.authenticode_hash(algorithm).unwrap().len(),
            "{algorithm:?}"
        );
    }
}
