//! Mutated test binaries must never make the parser panic. Errors are fine.

#[path = "../common/mod.rs"]
mod common;

use pers::PeFile;
#[cfg(feature = "authenticode")]
use pers::authenticode::HashAlgorithm;

/// A xorshift generator, so the test is reproducible without dependencies.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Access every structure of the file.
fn touch(data: &[u8]) {
    let Ok(pe) = PeFile::parse(data) else {
        return;
    };
    let _ = (
        pe.export_directory(),
        pe.exported_functions(),
        pe.imported_functions(),
    );
    let _ = (
        pe.delay_imported_functions(),
        pe.bound_import_descriptor(),
        pe.debug_directory(),
    );
    let _ = (
        pe.tls_callbacks(),
        pe.load_config_directory(),
        pe.com_descriptor(),
        pe.win_certificate(),
    );
    let _ = (pe.imp_hash(), pe.is_driver(), pe.sha256());
    if let Ok(Some(relocations)) = pe.base_relocations() {
        relocations.take(10_000).for_each(drop);
    }
    if let (Ok(Some(functions)), Ok(sections)) = (pe.exception_directory(), pe.section_headers()) {
        functions
            .iter()
            .for_each(|f| drop(f.unwind_info(data, sections)));
    }
    if let Ok(Some(entries)) = pe.debug_directory() {
        entries.iter().for_each(|e| drop(e.cv_info_pdb70(data)));
    }
    #[cfg(feature = "resources")]
    {
        let _ = (pe.resources(), pe.group_icons());
        if let Ok(icons) = pe.icons() {
            icons.for_each(drop);
        }
    }
    #[cfg(feature = "dotnet")]
    {
        let _ = (
            pe.metadata_tables_header(),
            pe.type_ref_hash(),
            pe.clr_module_version_ids(),
            pe.clr_com_type_lib_id(),
        );
    }
    #[cfg(feature = "authenticode")]
    {
        let _ = (
            pe.authenticode_info(),
            pe.crl_url_list(),
            pe.authenticode_hash(HashAlgorithm::Sha1),
        );
    }
}

#[test]
fn mutated_binaries_do_not_panic() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for entry in std::fs::read_dir(common::test_file("Binaries")).unwrap() {
        let original = std::fs::read(entry.unwrap().path()).unwrap();
        touch(&original);
        for round in 0..20 {
            let mut data = original.clone();
            if round % 2 == 0 {
                data.truncate(rng.next() as usize % (data.len() + 1));
            } else {
                for _ in 0..64 {
                    let index = rng.next() as usize % data.len().max(1);
                    if let Some(byte) = data.get_mut(index) {
                        *byte ^= (rng.next() >> 32) as u8;
                    }
                }
            }
            touch(&data);
        }
    }
}
