use crate::common::load;
use pers::editor::{AdditionalImport, PeEditor};

fn has_import(editor: &PeEditor, dll: &str, name: &str) -> bool {
    editor
        .pe()
        .unwrap()
        .imported_functions()
        .unwrap()
        .unwrap()
        .iter()
        .any(|i| i.dll == dll && i.name.as_deref() == Some(name))
}

#[test]
fn add_import_r_data_section() {
    let mut editor = PeEditor::new(load("chrome_elf.dll")).unwrap();
    editor.add_import("gdi32.dll", "StartPage").unwrap();

    assert!(has_import(&editor, "gdi32.dll", "StartPage"));
}

#[test]
fn add_import_to_not_existing_imp_desc_64_bit_executable() {
    let mut editor = PeEditor::new(load("add-import.exe")).unwrap();
    editor.add_import("gdi32.dll", "StartPage").unwrap();

    assert!(has_import(&editor, "gdi32.dll", "StartPage"));
}

#[test]
fn add_import_to_not_existing_imp_desc_multiple_64_bit_executable() {
    let mut editor = PeEditor::new(load("add-import.exe")).unwrap();
    let ai1 = AdditionalImport::new("gdi32.dll", ["StartPage", "EndDoc"]);
    let ai2 = AdditionalImport::new(
        "api-ms-win-core-errorhandling-l1-1-0.dll",
        ["SetUnhandledExceptionFilter"],
    );
    editor.add_imports(&[ai1, ai2]).unwrap();

    assert!(has_import(&editor, "gdi32.dll", "StartPage"));
    assert!(has_import(&editor, "gdi32.dll", "EndDoc"));
    assert!(has_import(
        &editor,
        "api-ms-win-core-errorhandling-l1-1-0.dll",
        "SetUnhandledExceptionFilter"
    ));
}

#[test]
fn add_import_to_existing_imp_desc_64_bit_executable() {
    let mut editor = PeEditor::new(load("add-import.exe")).unwrap();
    editor
        .add_imports(&[AdditionalImport::new("ADVAPI32.dll", ["RegCloseKey"])])
        .unwrap();

    assert!(has_import(&editor, "ADVAPI32.dll", "RegCloseKey"));
}

#[test]
fn add_import_keeps_existing_imports() {
    let data = load("add-import.exe");
    let before = pers::PeFile::parse(&data)
        .unwrap()
        .imported_functions()
        .unwrap()
        .unwrap()
        .len();
    let mut editor = PeEditor::new(data.clone()).unwrap();

    editor.add_import("gdi32.dll", "StartPage").unwrap();

    let after = editor
        .pe()
        .unwrap()
        .imported_functions()
        .unwrap()
        .unwrap()
        .len();
    assert_eq!(before + 1, after);
}

/// Regression test against an issue introduced in PeNet 2.4.1: writing the thunk data failed with
/// an out of range error.
#[test]
fn add_import_regression_1() {
    let mut editor = PeEditor::new(load("AddImportsRegression.exe")).unwrap();
    editor
        .add_imports(&[AdditionalImport::new(
            "test.dll",
            [
                "fn0000000140001000",
                "fn0000000140001C50",
                "fn0000000140001C54",
                "fn0000000140001C5C",
                "fn0000000140001C74",
                "fn0000000140001C7C",
                "fn0000000140001C84",
                "fn0000000140001CB4",
                "fn0000000140001CBC",
                "fn0000000140001E18",
            ],
        )])
        .unwrap();

    assert!(has_import(&editor, "test.dll", "fn0000000140001000"));
    assert!(has_import(&editor, "test.dll", "fn0000000140001E18"));
}
