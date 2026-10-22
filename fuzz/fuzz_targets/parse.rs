#![no_main]

use libfuzzer_sys::fuzz_target;
use pers::PeFile;
use pers::authenticode::HashAlgorithm;

fuzz_target!(|data: &[u8]| {
    let Ok(pe) = PeFile::parse(data) else {
        return;
    };
    let _ = (pe.exported_functions(), pe.imported_functions(), pe.delay_imported_functions());
    let _ = (pe.debug_directory(), pe.tls_callbacks(), pe.load_config_directory(), pe.imp_hash());
    if let Ok(Some(relocations)) = pe.base_relocations() {
        relocations.take(10_000).for_each(drop);
    }
    let _ = (pe.resources(), pe.group_icons());
    let _ = (pe.metadata_tables_header(), pe.type_ref_hash(), pe.clr_module_version_ids());
    let _ = (pe.authenticode_info(), pe.authenticode_hash(HashAlgorithm::Sha1));
});
