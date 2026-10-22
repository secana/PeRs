use crate::common::load;
use pers::PeFile;
use pers::editor::PeEditor;
use pers::pe::SectionCharacteristics;

#[test]
fn add_section_new_section_at_end_of_file() {
    let mut editor = PeEditor::new(load("add-section.exe")).unwrap();

    // Before adding the new section
    {
        let pe = editor.pe().unwrap();
        assert_eq!(27_648, pe.data().len());
        assert_eq!(6, pe.nt_headers().file_header.number_of_sections());
        assert_eq!(0xb000, pe.nt_headers().optional_header.size_of_image());
        assert_eq!(6, pe.section_headers().unwrap().len());
    }

    editor
        .add_section(
            ".newSec",
            100,
            SectionCharacteristics::from_bits_retain(0x40000040),
        )
        .unwrap();

    // After adding the new section
    let pe = editor.pe().unwrap();
    assert_eq!(28_160, pe.data().len());
    assert_eq!(7, pe.nt_headers().file_header.number_of_sections());
    assert_eq!(0xc000, pe.nt_headers().optional_header.size_of_image());
    let sections = pe.section_headers().unwrap();
    assert_eq!(7, sections.len());
    let new_section = sections.by_name(".newSec").unwrap();
    assert_eq!(100, new_section.virtual_size());
    assert_eq!(27_648, new_section.pointer_to_raw_data().get());
}

#[test]
fn add_section_with_too_long_name_fails() {
    let mut editor = PeEditor::new(load("add-section.exe")).unwrap();

    assert!(
        editor
            .add_section(".tooLongName", 100, SectionCharacteristics::MEM_READ)
            .is_err()
    );
}

#[test]
fn remove_section_section_removed() {
    let mut editor = PeEditor::new(load("remove-section.exe")).unwrap();
    editor.remove_section(".rsrc", true).unwrap();

    let pe = editor.pe().unwrap();
    let sections = pe.section_headers().unwrap();
    assert_eq!(5, sections.len());
    assert!(sections.by_name(".rsrc").is_none());
}

#[test]
fn remove_section_given_pe_file_returns_pe_with_removed_section() {
    let cases = [
        (
            true,
            "1e556b0da4925dec2b923de11d6806f8514021d4a8d4dcb741a210f19cbec567",
        ),
        (
            false,
            "e046941f6cf3a8c7905d0837400bf3d0527e24312d900f7bba94521da2c4ac8e",
        ),
    ];
    for (remove_content, expected_sha256) in cases {
        let mut editor = PeEditor::new(load("remove-section.exe")).unwrap();

        editor.remove_section(".rsrc", remove_content).unwrap();

        let data = editor.into_bytes();
        assert_eq!(
            expected_sha256,
            hex::encode(PeFile::parse(&data).unwrap().sha256()),
            "{remove_content}"
        );
    }
}

/// Offset of a field of the optional header in `add-section.exe`.
fn optional_header_field(data: &[u8], field: usize) -> usize {
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    e_lfanew + 0x18 + field
}

#[test]
fn add_section_without_space_for_the_section_header_fails() {
    let mut data = load("add-section.exe");
    let section_table_end = {
        let pe = PeFile::parse(&data).unwrap();
        let nt = pe.nt_headers();
        nt.offset
            + 0x18
            + nt.file_header.size_of_optional_header() as usize
            + nt.file_header.number_of_sections() as usize * 0x28
    };
    let size_of_headers = optional_header_field(&data, 0x3C);
    data[size_of_headers..size_of_headers + 4]
        .copy_from_slice(&(section_table_end as u32).to_le_bytes());
    let mut editor = PeEditor::new(data).unwrap();

    assert!(matches!(
        editor.add_section(".newSec", 100, SectionCharacteristics::MEM_READ),
        Err(pers::Error::InvalidOperation(_))
    ));
}

#[test]
fn add_section_with_zero_alignment_fails() {
    let mut data = load("add-section.exe");
    let section_alignment = optional_header_field(&data, 0x20);
    data[section_alignment..section_alignment + 4].copy_from_slice(&0u32.to_le_bytes());
    let mut editor = PeEditor::new(data).unwrap();

    assert!(matches!(
        editor.add_section(".newSec", 100, SectionCharacteristics::MEM_READ),
        Err(pers::Error::InvalidOperation(_))
    ));
}
