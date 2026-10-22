use crate::common::load;
use crate::common::raw_dot_net_structures::RAW_META_DATA_TABLES_HDR;
use pers::PeFile;
use pers::net::MetadataTablesHeader;

fn module_name(pe: &PeFile) -> String {
    let tables_stream = pe.metadata_tables_header().unwrap().unwrap();
    let strings_stream = pe.metadata_strings().unwrap().unwrap();
    let module = &tables_stream.tables().unwrap().module[0];
    strings_stream.get(module.name).unwrap().into_owned()
}

#[test]
fn meta_data_tables_hdr_constructor_works_test() {
    let h = MetadataTablesHeader::parse(RAW_META_DATA_TABLES_HDR, 0x2)
        .unwrap()
        .header;

    assert_eq!(0x55443322, h.reserved1());
    assert_eq!(0x66, h.major_version());
    assert_eq!(0x77, h.minor_version());
    assert_eq!(0x88, h.heap_sizes().bits());
    assert_eq!(0x99, h.reserved2());
    assert_eq!(0xffffffffffffffff, h.mask_valid().bits());
    assert_eq!(0xaa99887766554433, h.mask_sorted());
}

#[test]
fn read_meta_data_tables_hdr_without_extra_data() {
    let data = load("HelloWorld.exe");
    let pe = PeFile::parse(&data).unwrap();
    let tables_stream = pe.metadata_tables_header().unwrap().unwrap();

    assert!(!tables_stream.has_extra_data());
    assert_eq!(None, tables_stream.extra_data().unwrap());
    assert_eq!("HelloWorld.exe", module_name(&pe));
}

#[test]
fn read_meta_data_tables_hdr_with_extra_data() {
    let data = load("HelloWorld.TablesStream.ExtraData.exe");
    let pe = PeFile::parse(&data).unwrap();
    let tables_stream = pe.metadata_tables_header().unwrap().unwrap();

    assert!(tables_stream.has_extra_data());
    assert_eq!(Some(12345678), tables_stream.extra_data().unwrap());
    assert_eq!("HelloWorld.exe", module_name(&pe));
}

fn extra_data(editor: &pers::editor::PeEditor) -> Option<u32> {
    let pe = editor.pe().unwrap();
    pe.metadata_tables_header()
        .unwrap()
        .unwrap()
        .extra_data()
        .unwrap()
}

#[test]
fn write_null_extra_data_to_header_without_extra_data_should_not_throw() {
    let mut editor = pers::editor::PeEditor::new(load("HelloWorld.exe")).unwrap();

    editor.set_metadata_tables_extra_data(None).unwrap();
    assert_eq!(None, extra_data(&editor));
}

#[test]
fn write_non_null_extra_data_to_header_with_extra_data_should_not_throw() {
    let mut editor =
        pers::editor::PeEditor::new(load("HelloWorld.TablesStream.ExtraData.exe")).unwrap();

    editor.set_metadata_tables_extra_data(Some(1234)).unwrap();
    assert_eq!(Some(1234), extra_data(&editor));
}

#[test]
fn write_non_null_extra_data_to_header_without_extra_data_should_throw() {
    let mut editor = pers::editor::PeEditor::new(load("HelloWorld.exe")).unwrap();

    assert!(matches!(
        editor.set_metadata_tables_extra_data(Some(1234)),
        Err(pers::Error::InvalidOperation(_))
    ));
}

#[test]
fn write_null_extra_data_to_header_with_extra_data_should_throw() {
    let mut editor =
        pers::editor::PeEditor::new(load("HelloWorld.TablesStream.ExtraData.exe")).unwrap();

    assert!(matches!(
        editor.set_metadata_tables_extra_data(None),
        Err(pers::Error::InvalidOperation(_))
    ));
}
