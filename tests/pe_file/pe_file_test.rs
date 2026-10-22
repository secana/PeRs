use std::fs::File;

use crate::common::{binary, load};
use pers::pe::{ResourceName, ResourceType};
use pers::{MmFile, PeFile};

const PE_FILE_CASES: [(&str, bool); 4] = [
    ("firefox_x64.exe", true),
    ("firefox_x86.exe", true),
    ("NetFrameworkConsole.exe", true),
    ("notPeFile.txt", false),
];

#[test]
fn is_pe_file_given_stream_true_or_false() {
    for (file, expected) in PE_FILE_CASES {
        let mut fs = File::open(binary(file)).unwrap();
        assert_eq!(expected, PeFile::is_pe_reader(&mut fs).unwrap(), "{file}");
    }
}

#[test]
fn is_pe_file_given_buffer_true_or_false() {
    let cases = [
        ("firefox_x64.exe", true),
        ("firefox_x86_2.exe", true),
        ("NetFrameworkConsole.exe", true),
        ("notPeFile.txt", false),
    ];
    for (file, expected) in cases {
        assert_eq!(expected, PeFile::is_pe(&load(file)), "{file}");
    }
}

#[test]
fn is_pe_file_given_mm_file_true_or_false() {
    for (file, expected) in PE_FILE_CASES {
        let mmf = MmFile::open_read_only(binary(file)).unwrap();
        assert_eq!(expected, PeFile::is_pe(&mmf), "{file}");
    }
}

#[test]
fn try_parse_given_buffer_true_or_false() {
    for (file, expected) in PE_FILE_CASES {
        let data = load(file);
        assert_eq!(
            expected,
            PeFile::try_from(data.as_slice()).is_ok(),
            "{file}"
        );
    }
}

#[test]
fn try_parse_given_mmf_true_or_false() {
    for (file, expected) in PE_FILE_CASES {
        let mmf = MmFile::open_read_only(binary(file)).unwrap();
        assert_eq!(expected, PeFile::parse(&mmf).is_ok(), "{file}");
    }
}

const FIREFOX_X64_SHA256: &str = "377d3b741d8447b9bbd5f6fa700151a6ce8412ca15792ba4eaaa3174b1763ba4";

#[test]
fn sha256_given_a_pe_file1_returns_correct_hash() {
    let data = load("firefox_x64.exe");

    assert_eq!(
        FIREFOX_X64_SHA256,
        hex::encode(PeFile::parse(&data).unwrap().sha256())
    );
}

#[test]
fn sha256_given_a_memory_mapped_pe_file_returns_correct_hash() {
    let mmf = MmFile::open_read_only(binary("firefox_x64_copy1.exe")).unwrap();

    assert_eq!(
        FIREFOX_X64_SHA256,
        hex::encode(PeFile::parse(&mmf).unwrap().sha256())
    );
}

#[test]
fn sha1_given_a_pe_file_returns_correct_hash() {
    let data = load("firefox_x64.exe");

    assert_eq!(
        "5faf53976b7a4c2ffaf96581803c72cd09484b39",
        hex::encode(PeFile::parse(&data).unwrap().sha1())
    );
}

#[test]
fn md5_given_a_pe_file_returns_correct_hash() {
    let data = load("firefox_x64.exe");

    assert_eq!(
        "fa64b4aeb420a6c292f877e90d0670a5",
        hex::encode(PeFile::parse(&data).unwrap().md5())
    );
}

#[test]
fn is_32_bit_given_pe_files_returns_correct_bitness() {
    let cases = [
        ("arm_binary.dll", true),
        ("arm_dotnet_binary.dll", true),
        ("old_firefox_x86.exe", true),
        ("firefox_invalid_x64.exe", false),
        ("dotnet_x64.dll", false),
        ("osx_vb_netcore.dll", false),
    ];
    for (file, is_32_bit) in cases {
        let data = load(file);
        assert_eq!(
            is_32_bit,
            PeFile::parse(&data).unwrap().is_32_bit(),
            "{file}"
        );
    }
}

#[test]
fn resource_entry_is_id_entry_has_name_unknown() {
    let data = load("VB40032-2.DLL");
    let pe_file = PeFile::parse(&data).unwrap();
    let root = pe_file.resource_directory().unwrap().unwrap();
    let de = &root.entries[6];

    assert_eq!(ResourceName::Id(13), de.name);
    assert_eq!(3592, de.directory().unwrap().entries[0].raw.id());
    assert_eq!(None, ResourceType::from(13).name());
}

#[test]
fn imported_function_delay_import_parsed_delay_imports() {
    let data = load("chrome_elf.dll");
    let pe_file = PeFile::parse(&data).unwrap();

    assert!(
        pe_file
            .delay_imported_functions()
            .unwrap()
            .unwrap()
            .iter()
            .any(|i| i.dll == "WINMM.dll" && i.name.as_deref() == Some("timeGetTime"))
    );
}

#[test]
fn exported_functions_with_forwarded_functions_parsed_forwarded_functions() {
    let data = load("win_test.dll");
    let pe_file = PeFile::parse(&data).unwrap();
    let exports = pe_file.exported_functions().unwrap().unwrap();
    let forward_exports: Vec<_> = exports.iter().filter(|e| e.is_forwarded()).collect();

    assert_eq!(180, forward_exports.len());
    let enter_critical_section = forward_exports
        .iter()
        .find(|e| e.name.as_deref() == Some("EnterCriticalSection"))
        .unwrap();
    assert_eq!(
        Some("NTDLL.RtlEnterCriticalSection"),
        enter_critical_section.forward_name.as_deref()
    );
}

#[test]
fn is_driver_given_a_pe_file_returns_driver_or_not() {
    let cases = [
        ("firefox_x64.exe", false),
        ("TLSCallback_x86.exe", false),
        ("NetCoreConsole.dll", false),
        ("win_test.dll", false),
        ("krnl_test.sys", true),
    ];
    for (file, is_driver) in cases {
        let data = load(file);
        assert_eq!(
            is_driver,
            PeFile::parse(&data).unwrap().is_driver(),
            "{file}"
        );
    }
}

#[test]
fn is_signed_path_to_signed_binary_returns_signed_or_not() {
    let cases = [
        ("firefox_x86.exe", true),
        ("firefox_x64.exe", true),
        ("TLSCallback_x86.exe", false),
    ];
    for (file, expected) in cases {
        let data = load(file);
        assert_eq!(
            expected,
            PeFile::parse(&data).unwrap().is_signed(),
            "{file}"
        );
    }
}

#[cfg(windows)]
#[test]
fn is_signed_path_to_signed_windows_binary_returns_signed() {
    for file in [
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\explorer.exe",
    ] {
        let data = std::fs::read(file).unwrap();
        assert!(PeFile::parse(&data).unwrap().is_signed(), "{file}");
    }
}

#[test]
fn file_kind_given_pe_files_returns_bitness_dll_and_exe() {
    // (file, is_64_bit, is_dll, is_exe)
    let cases = [
        ("firefox_x64.exe", true, false, true),
        ("firefox_x86.exe", false, false, true),
        ("chrome_elf.dll", true, true, true),
        ("arm_binary.dll", false, true, true),
    ];
    for (file, is_64_bit, is_dll, is_exe) in cases {
        let data = load(file);
        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(is_64_bit, pe.is_64_bit(), "{file}");
        assert_eq!(is_dll, pe.is_dll(), "{file}");
        assert_eq!(is_exe, pe.is_exe(), "{file}");
    }
}

#[cfg(feature = "dotnet")]
#[test]
fn is_dot_net_given_pe_files_returns_true_for_clr_files() {
    let cases = [
        ("NetCoreConsole.dll", true),
        ("NetFrameworkConsole.exe", true),
        ("firefox_x64.exe", false),
    ];
    for (file, expected) in cases {
        let data = load(file);
        assert_eq!(
            expected,
            PeFile::parse(&data).unwrap().is_dot_net(),
            "{file}"
        );
    }
}

#[test]
fn section_table_offset_to_rva_round_trip() {
    let data = load("pdb_guid.exe");
    let pe = PeFile::parse(&data).unwrap();
    let sections = pe.section_headers().unwrap();

    let mapped = sections
        .iter()
        .filter(|s| s.virtual_size() > 0x10 && s.size_of_raw_data() > 0x10);
    for section in mapped {
        let rva = pers::Rva(section.virtual_address().get() + 0x10);
        let offset = sections.rva_to_offset(rva).unwrap();
        assert_eq!(
            section.pointer_to_raw_data().get() + 0x10,
            offset.get(),
            "{}",
            section.name()
        );
        assert_eq!(
            rva,
            sections.offset_to_rva(offset).unwrap(),
            "{}",
            section.name()
        );
    }
}

#[test]
fn data_directory_is_present() {
    let data = load("firefox_x64.exe");
    let pe = PeFile::parse(&data).unwrap();

    assert!(
        pe.data_directory(pers::pe::DataDirectoryType::Import)
            .is_present()
    );
    assert!(
        !pe.data_directory(pers::pe::DataDirectoryType::ComDescriptor)
            .is_present()
    );
}

#[test]
fn base_relocations_given_pe_files_returns_blocks() {
    let cases = [
        ("firefox_x64.exe", 6, 0x35000),
        ("firefox_x86.exe", 45, 0x1000),
    ];
    for (file, count, first_virtual_address) in cases {
        let data = load(file);
        let pe = PeFile::parse(&data).unwrap();
        let blocks: Vec<_> = pe
            .base_relocations()
            .unwrap()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(count, blocks.len(), "{file}");
        assert_eq!(
            pers::Rva(first_virtual_address),
            blocks[0].virtual_address,
            "{file}"
        );
        assert!(
            blocks
                .iter()
                .all(|b| b.entries().len() as u32 == (b.size_of_block - 8) / 2),
            "{file}"
        );
    }
}

#[test]
fn load_config_directory_given_pe_files_returns_security_cookie() {
    let cases = [
        ("firefox_x64.exe", 0x1_4004_0010),
        ("firefox_x86.exe", 0x43_0008),
    ];
    for (file, cookie) in cases {
        let data = load(file);
        let load_config = PeFile::parse(&data)
            .unwrap()
            .load_config_directory()
            .unwrap()
            .unwrap();
        assert_eq!(cookie, load_config.security_cookie(), "{file}");
    }
}

#[test]
fn bound_import_descriptor_given_file_without_bound_imports_returns_none() {
    let data = load("firefox_x64.exe");

    assert!(
        PeFile::parse(&data)
            .unwrap()
            .bound_import_descriptor()
            .unwrap()
            .is_none()
    );
}

#[test]
fn bound_import_descriptor_in_the_headers_is_parsed() {
    let mut data = load("firefox_x64.exe");
    let (directory_entry, descriptor_offset) = {
        let pe = PeFile::parse(&data).unwrap();
        let nt = pe.nt_headers();
        let table_end = nt.offset
            + 0x18
            + nt.file_header.size_of_optional_header() as usize
            + nt.file_header.number_of_sections() as usize * 0x28;
        let directory_entry = nt.offset + 0x18 + 0x70 + 11 * 8;
        (directory_entry, table_end.next_multiple_of(8))
    };
    // Descriptor: time stamp 0x11223344, module name offset 0x10, no forwarder refs.
    data[descriptor_offset..descriptor_offset + 8]
        .copy_from_slice(&[0x44, 0x33, 0x22, 0x11, 0x10, 0x00, 0x00, 0x00]);
    data[directory_entry..directory_entry + 4]
        .copy_from_slice(&(descriptor_offset as u32).to_le_bytes());
    data[directory_entry + 4..directory_entry + 8].copy_from_slice(&16u32.to_le_bytes());

    let pe = PeFile::parse(&data).unwrap();
    let descriptor = pe.bound_import_descriptor().unwrap().unwrap();
    assert_eq!(0x11223344, descriptor.time_date_stamp());
    assert_eq!(0x10, descriptor.offset_module_name());
}
