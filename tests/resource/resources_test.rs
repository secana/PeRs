use crate::common::{load, test_file};
use pers::PeFile;
use pers::resource::{VersionKey, VsVersionInfo};

fn with_version_info(file: &str, check: impl FnOnce(VsVersionInfo)) {
    let data = load(file);
    let pe_file = PeFile::parse(&data).unwrap();
    check(pe_file.resources().unwrap().unwrap().version_info.unwrap());
}

#[test]
fn resources_given_a_pe_file1_vs_version_info_set() {
    with_version_info("firefox_invalid_x64.exe", |vs_version_info| {
        assert_eq!(0x03E8, vs_version_info.header.w_length);
        assert_eq!(0x0034, vs_version_info.header.w_value_length);
        assert_eq!(0x0000, vs_version_info.header.w_type);
        assert_eq!("VS_VERSION_INFO", vs_version_info.header.sz_key);

        let fixed = vs_version_info.fixed_file_info.unwrap();
        assert_eq!(0xFEEF04BD, fixed.dw_signature());
        assert_eq!(0x00010000, fixed.dw_struc_version());
        assert_eq!(0x00390000, fixed.dw_file_version_ms());
        assert_eq!(0x00021995, fixed.dw_file_version_ls());
        assert_eq!(0x00390000, fixed.dw_product_version_ms());
        assert_eq!(0x00020000, fixed.dw_product_version_ls());
        assert_eq!(0x0000003F, fixed.dw_file_flags_mask());
        assert_eq!(0x00000000, fixed.dw_file_flags());
        assert_eq!(0x00000004, fixed.dw_file_os());
        assert_eq!(0x00000002, fixed.dw_file_type());
        assert_eq!(0x00000000, fixed.dw_file_sub_type());
        assert_eq!(0x00000000, fixed.dw_file_date_ms());
        assert_eq!(0x00000000, fixed.dw_file_date_ls());
        assert_eq!([57, 0, 2, 0x1995], fixed.file_version());

        let string_file_info = vs_version_info.string_file_info.unwrap();
        assert_eq!(0x0346, string_file_info.header.w_length);
        assert_eq!(0x0000, string_file_info.header.w_value_length);
        assert_eq!(0x0001, string_file_info.header.w_type);
        assert_eq!("StringFileInfo", string_file_info.header.sz_key);

        let table = &string_file_info.string_tables[0];
        assert_eq!(0x0322, table.header.w_length);
        assert_eq!(0x0000, table.header.w_value_length);
        assert_eq!(0x0001, table.header.w_type);
        assert_eq!("000004b0", table.header.sz_key);

        assert_eq!(0x0018, table.strings[0].header.w_length);
        assert_eq!(0x0000, table.strings[0].header.w_value_length);
        assert_eq!(0x0001, table.strings[0].header.w_type);
        assert_eq!("Comments", table.strings[0].header.sz_key);

        assert_eq!(0x00AC, table.strings[1].header.w_length);
        assert_eq!(0x0044, table.strings[1].header.w_value_length);
        assert_eq!(0x0001, table.strings[1].header.w_type);
        assert_eq!("LegalCopyright", table.strings[1].header.sz_key);
        assert_eq!(
            "\u{00a9}Firefox and Mozilla Developers; available under the MPL 2 license.",
            table.strings[1].value
        );

        // ... more String entries ...

        assert_eq!(0x0036, table.strings[10].header.w_length);
        assert_eq!(0x000F, table.strings[10].header.w_value_length);
        assert_eq!(0x0001, table.strings[10].header.w_type);
        assert_eq!("BuildID", table.strings[10].header.sz_key);
        assert_eq!("20171206182557", table.strings[10].value);

        assert_eq!(
            Some("\u{00a9}Firefox and Mozilla Developers; available under the MPL 2 license."),
            table.get(VersionKey::LegalCopyright)
        );
        assert_eq!(
            Some("Mozilla Corporation"),
            table.get(VersionKey::CompanyName)
        );
        assert_eq!(Some("Firefox"), table.get(VersionKey::FileDescription));
        assert_eq!(Some("57.0.2"), table.get(VersionKey::FileVersion));
        assert_eq!(Some("57.0.2"), table.get(VersionKey::ProductVersion));
        assert_eq!(Some("Firefox"), table.get(VersionKey::InternalName));
        assert_eq!(
            Some("Firefox is a Trademark of The Mozilla Foundation."),
            table.get(VersionKey::LegalTrademarks)
        );
        assert_eq!(Some("firefox.exe"), table.get(VersionKey::OriginalFilename));
        assert_eq!(Some("Firefox"), table.get(VersionKey::ProductName));
        assert_eq!(Some("20171206182557"), table.value("BuildID"));

        let var_file_info = vs_version_info.var_file_info.unwrap();
        assert_eq!(0x0044, var_file_info.header.w_length);
        assert_eq!(0x0000, var_file_info.header.w_value_length);
        assert_eq!(0x0001, var_file_info.header.w_type);
        assert_eq!("VarFileInfo", var_file_info.header.sz_key);

        assert_eq!(0x0024, var_file_info.children[0].header.w_length);
        assert_eq!(0x0004, var_file_info.children[0].header.w_value_length);
        assert_eq!(0x0000, var_file_info.children[0].header.w_type);
        assert_eq!("Translation", var_file_info.children[0].header.sz_key);
        assert_eq!(0x04b00000, var_file_info.children[0].value[0]);
    });
}

#[test]
fn resources_given_a_pe_file2_vs_version_info_set() {
    with_version_info("pidgin.exe", |vs_version_info| {
        assert_eq!(0x0374, vs_version_info.header.w_length);
        assert_eq!(0x0034, vs_version_info.header.w_value_length);
        assert_eq!(0x0000, vs_version_info.header.w_type);
        assert_eq!("VS_VERSION_INFO", vs_version_info.header.sz_key);

        let fixed = vs_version_info.fixed_file_info.unwrap();
        assert_eq!(0xFEEF04BD, fixed.dw_signature());
        assert_eq!(0x00010000, fixed.dw_struc_version());
        assert_eq!(0x0002000A, fixed.dw_file_version_ms());
        assert_eq!(0x000B0000, fixed.dw_file_version_ls());
        assert_eq!(0x0002000A, fixed.dw_product_version_ms());
        assert_eq!(0x000B0000, fixed.dw_product_version_ls());
        assert_eq!(0x00000000, fixed.dw_file_flags_mask());
        assert_eq!(0x00000000, fixed.dw_file_flags());
        assert_eq!(0x00000004, fixed.dw_file_os());
        assert_eq!(0x00000001, fixed.dw_file_type());
        assert_eq!(0x00000000, fixed.dw_file_sub_type());
        assert_eq!(0x00000000, fixed.dw_file_date_ms());
        assert_eq!(0x00000000, fixed.dw_file_date_ls());
        assert_eq!([2, 10, 11, 0], fixed.product_version());

        let string_file_info = vs_version_info.string_file_info.unwrap();
        assert_eq!(0x02D4, string_file_info.header.w_length);
        assert_eq!(0x0000, string_file_info.header.w_value_length);
        assert_eq!(0x0001, string_file_info.header.w_type);
        assert_eq!("StringFileInfo", string_file_info.header.sz_key);

        let table = &string_file_info.string_tables[0];
        assert_eq!(0x02B0, table.header.w_length);
        assert_eq!(0x0000, table.header.w_value_length);
        assert_eq!(0x0001, table.header.w_type);
        assert_eq!("040904B0", table.header.sz_key);

        assert_eq!(0x005E, table.strings[0].header.w_length);
        assert_eq!(0x001F, table.strings[0].header.w_value_length);
        assert_eq!(0x0001, table.strings[0].header.w_type);
        assert_eq!("CompanyName", table.strings[0].header.sz_key);
        assert_eq!("The Pidgin developer community", table.strings[0].value);

        // ... more String entries ...

        assert_eq!(0x0034, table.strings[7].header.w_length);
        assert_eq!(0x0008, table.strings[7].header.w_value_length);
        assert_eq!(0x0001, table.strings[7].header.w_type);
        assert_eq!("ProductVersion", table.strings[7].header.sz_key);
        assert_eq!("2.10.11", table.strings[7].value);

        let var_file_info = vs_version_info.var_file_info.unwrap();
        assert_eq!(0x0044, var_file_info.header.w_length);
        assert_eq!(0x0000, var_file_info.header.w_value_length);
        assert_eq!(0x0001, var_file_info.header.w_type);
        assert_eq!("VarFileInfo", var_file_info.header.sz_key);

        assert_eq!(0x0024, var_file_info.children[0].header.w_length);
        assert_eq!(0x0004, var_file_info.children[0].header.w_value_length);
        assert_eq!(0x0000, var_file_info.children[0].header.w_type);
        assert_eq!("Translation", var_file_info.children[0].header.sz_key);
        assert_eq!(0x04b00409, var_file_info.children[0].value[0]);
    });
}

fn assert_original_filename_and_translation(file: &str, original_filename: &str) {
    with_version_info(file, |vs_version_info| {
        let string_file_info = vs_version_info.string_file_info.unwrap();
        assert_eq!(
            Some(original_filename),
            string_file_info.string_tables[0].get(VersionKey::OriginalFilename)
        );
        assert_eq!(
            "Translation",
            vs_version_info.var_file_info.unwrap().children[0]
                .header
                .sz_key
        );
    });
}

#[test]
fn resources_given_a_pe_file3_vs_version_info_set() {
    assert_original_filename_and_translation("NetFrameworkConsole.exe", "NetFrameworkConsole.exe");
}

#[test]
fn resources_given_a_pe_file4_vs_version_info_set() {
    assert_original_filename_and_translation("firefox_x86.exe", "firefox.exe");
}

#[test]
fn resources_given_pe_file_with_two_version_infos_vs_version_info_set_to_first_one() {
    assert_original_filename_and_translation(
        "pidgin_with_additional_firefox_version_entry.exe",
        "pidgin.exe",
    );
}

fn icons(file: &str) -> Vec<Vec<u8>> {
    let data = load(file);
    PeFile::parse(&data)
        .unwrap()
        .icons()
        .unwrap()
        .map(|icon| icon.into_owned())
        .collect()
}

fn group_icon_counts(file: &str) -> Vec<usize> {
    let data = load(file);
    PeFile::parse(&data)
        .unwrap()
        .group_icons()
        .unwrap()
        .iter()
        .map(Vec::len)
        .collect()
}

#[test]
fn icons_given_pe_files_icons_parsed() {
    let cases = [
        ("firefox_x64.exe", 18),
        ("firefox_x86.exe", 18),
        ("HelloWorld.exe", 0),
        ("chrome_elf.dll", 0),
    ];
    for (file, expected_icons) in cases {
        assert_eq!(expected_icons, icons(file).len(), "{file}");
    }
}

#[test]
fn icons_given_pe_files_icons_in_groups_parsed() {
    assert_eq!(vec![4, 4, 2, 2, 2, 4], group_icon_counts("firefox_x64.exe"));
    assert!(group_icon_counts("HelloWorld.exe").is_empty());
}

#[test]
fn icons_given_pe_files_and_icon_included_in_pe_file_found_icon_contains_given_icon() {
    let cases = [
        ("firefox_x64.exe", "Icons/firefox_x64.exe/ico"),
        ("pidgin.exe", "Icons/pidgin.exe/ico"),
    ];
    for (file, icon_directory) in cases {
        let icons = icons(file);
        for icon_file in std::fs::read_dir(test_file(icon_directory)).unwrap() {
            let icon = std::fs::read(icon_file.unwrap().path()).unwrap();
            assert!(icons.contains(&icon), "{file}");
        }
    }
}

#[test]
fn ico_icons_given_pe_files_and_icon_not_included_in_pe_file_found_icon_do_not_contains_given_icon()
{
    let cases = [
        ("firefox_x64.exe", "Icons/pidgin.exe/ico/Icon5.ico"),
        ("pidgin.exe", "Icons/firefox_x64.exe/ico/Icon1.ico"),
    ];
    for (file, icon_file) in cases {
        let icon = std::fs::read(test_file(icon_file)).unwrap();
        assert!(!icons(file).contains(&icon), "{file}");
    }
}

#[test]
fn ico_icons_given_pe_file_with_icon_without_icon_group_directory_entry_all_icons_are_extracted() {
    assert_eq!(
        10,
        icons("pidgin_with_one_icon_without_IconGroupDirectoryEntry.exe").len()
    );
}

#[test]
fn ico_icons_given_pe_file_without_icon_group_directory_all_icons_are_extracted() {
    assert_eq!(9, icons("pidgin_without_groupIconDirectory.exe").len());
}

#[test]
fn ico_icons_given_pe_file_with_icon_group_directory_entry_reference_to_non_existing_icon_empty_reference_is_ignored()
 {
    assert_eq!(
        8,
        group_icon_counts("pidgin_with_iconGroupEntry_without_icon.exe")[0]
    );
}

#[test]
fn ico_icons_given_pe_file_with_icon_with_multiple_corresponding_icon_group_entries_icon_included_in_all_corresponding_icon_groups()
 {
    let data = load("pidgin_with_double_iconGroupEntries.exe");
    let groups = PeFile::parse(&data).unwrap().group_icons().unwrap();

    assert_eq!(groups[0][0], groups[1][0]);
}

#[test]
fn ico_icons_given_pe_file_with_multiple_icons_with_the_same_id_all_icons_with_same_id_are_included_in_corresponding_icon_group()
 {
    assert_eq!(
        10,
        group_icon_counts("pidgin_two_icons_with_same_id.exe")[0]
    );
}

#[test]
fn ico_icons_given_pe_file_with_manipulated_group_icon_directory_pe_file_is_parsed() {
    assert_eq!(
        vec![9, 0, 2, 9, 0],
        group_icon_counts("pidgin_manipulated_GroupIconDirectory.exe")
    );
    assert_eq!(
        vec![9, 0, 2, 9, 0],
        group_icon_counts("pidgin_manipulated_GroupIconDirectory_withNullIcon.exe")
    );
    assert_eq!(
        vec![5],
        group_icon_counts("filezilla_dll_without_Version.dll")
    );
}

#[test]
fn ico_icons_given_pe_file_with_manipulated_icons_pe_file_is_parsed() {
    assert_eq!(13, icons("pidgin_manipulated_Icons.exe").len());
}

#[test]
fn png_icons_are_borrowed_from_the_file() {
    let data = load("firefox_x64.exe");
    let pe_file = PeFile::parse(&data).unwrap();

    assert!(
        pe_file
            .icons()
            .unwrap()
            .any(|icon| matches!(icon, std::borrow::Cow::Borrowed(_)))
    );
}
