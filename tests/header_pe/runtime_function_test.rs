use crate::common::load;
use crate::common::raw_structures::RAW_RUNTIME_FUNCTION;
use pers::pe::RuntimeFunction;
use pers::{PeFile, Rva};

#[test]
fn runtime_function_constructor_works_test() {
    let f = RuntimeFunction::parse(RAW_RUNTIME_FUNCTION, 2).unwrap();

    assert_eq!(Rva(0x33221100), f.function_start());
    assert_eq!(Rva(0x77665544), f.function_end());
    assert_eq!(Rva(0xbbaa9988), f.unwind_info_address());
}

#[test]
fn runtime_function_resolves_unwind_info() {
    let data = load("firefox_x64.exe");
    let pe_file = PeFile::parse(&data).unwrap();
    let functions = pe_file.exception_directory().unwrap().unwrap();
    let sections = pe_file.section_headers().unwrap();

    assert!(!functions.is_empty());
    assert!(
        functions
            .iter()
            .all(|f| f.unwind_info(&data, sections).is_ok())
    );
}
