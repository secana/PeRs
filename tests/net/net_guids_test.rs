use crate::common::load;
use pers::PeFile;
use uuid::Uuid;

#[test]
fn net_guid_module_version_id_not_clr_pe_empty() {
    let data = load("win_test.dll");
    let pe = PeFile::parse(&data).unwrap();
    assert_eq!(None, pe.clr_module_version_ids().unwrap());
}

#[test]
fn net_guid_module_version_id_clr_pe_not_empty() {
    let data = load("NetFrameworkConsole.exe");
    let pe = PeFile::parse(&data).unwrap();
    assert_eq!(
        Uuid::parse_str("5250e853-c17a-4e76-adb3-0a716ec8af5d").unwrap(),
        pe.clr_module_version_ids().unwrap().unwrap()[0]
    );
}

#[test]
fn net_guid_com_type_lib_id_not_clr_pe_null() {
    let data = load("win_test.dll");
    let pe = PeFile::parse(&data).unwrap();
    assert_eq!(None, pe.clr_com_type_lib_id().unwrap());
}

#[test]
fn net_guid_com_type_lib_id_clr_pe_not_empty() {
    let data = load("NetFrameworkConsole.exe");
    let pe = PeFile::parse(&data).unwrap();
    assert_eq!(
        Some(Uuid::parse_str("a782d109-aa8f-427b-8dcf-1c786054c7e0").unwrap()),
        pe.clr_com_type_lib_id().unwrap()
    );
}
