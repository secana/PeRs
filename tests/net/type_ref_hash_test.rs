use crate::common::load;
use pers::PeFile;

fn type_ref_hash(name: &str) -> Option<String> {
    let data = load(name);
    let pe = PeFile::parse(&data).unwrap();
    pe.type_ref_hash().unwrap().map(hex::encode)
}

#[test]
fn dot_net_file_returns_correct_type_ref_hash() {
    for (file, hash) in [
        (
            "NetCoreConsole.dll",
            "9b435fef12d55da7073890330a9a4d7f6e02194aa63e6093429db574407458ba",
        ),
        (
            "NetFrameworkConsole.exe",
            "c4bc255f816ae338fba805256b078bb023d339d2b80dc84a21444367539038cb",
        ),
        (
            "osx_vb_netcore.dll",
            "5fda416c838f34364173ed8c3cd7181dad676aaf7e8b2b37e54953405462f42d",
        ),
        (
            "arm_dotnet_binary.dll",
            "d633db771449e2c37e1689a8c291a4f4646ce156652a9dad5f67394c0d92a8c4",
        ),
    ] {
        assert_eq!(Some(hash), type_ref_hash(file).as_deref(), "{file}");
    }
}

#[test]
fn not_dot_net_file_returns_null() {
    for file in ["krnl_test.sys", "No_SEH.exe", "win_test.dll"] {
        assert_eq!(None, type_ref_hash(file), "{file}");
    }
}
