use crate::common::raw_dot_net_structures::RAW_IMAGE_COR20_HEADER;
use pers::Rva;
use pers::pe::{ComFlags, ImageCor20Header};

#[test]
fn image_cor20_header_constructor_works_test() {
    let h = ImageCor20Header::parse(RAW_IMAGE_COR20_HEADER, 3).unwrap();

    assert_eq!(0x33221100, h.cb());
    assert_eq!(0x5544, h.major_runtime_version());
    assert_eq!(0x7766, h.minor_runtime_version());
    assert_eq!(Rva(0xbbaa9988), h.meta_data().virtual_address());
    assert_eq!(0xffeeddcc, h.meta_data().size());
    assert!(h.flags().contains(ComFlags::IL_LIBRARY));
    assert!(h.flags().contains(ComFlags::TRACK_DEBUG_DATA));
    assert!(!h.flags().contains(ComFlags::REQUIRES_32BIT));
    assert_eq!(0x88776655, h.entry_point_token());
    assert_eq!(Rva(0xccbbaa99), h.resources().virtual_address());
    assert_eq!(0x11ffeedd, h.resources().size());
    assert_eq!(Rva(0xddccbbaa), h.strong_name_signature().virtual_address());
    assert_eq!(0x2211ffee, h.strong_name_signature().size());
    assert_eq!(Rva(0xeeddccbb), h.code_manager_table().virtual_address());
    assert_eq!(0x332211ff, h.code_manager_table().size());
    assert_eq!(Rva(0xffeeddcc), h.v_table_fixups().virtual_address());
    assert_eq!(0x44332211, h.v_table_fixups().size());
    assert_eq!(
        Rva(0x11ffeedd),
        h.export_address_table_jumps().virtual_address()
    );
    assert_eq!(0x55443322, h.export_address_table_jumps().size());
    assert_eq!(Rva(0x2211ffee), h.managed_native_header().virtual_address());
    assert_eq!(0x66554433, h.managed_native_header().size());
}

fn names(flags: ComFlags) -> Vec<&'static str> {
    flags.iter_names().map(|(name, _)| name).collect()
}

#[test]
fn resolve_com_flags_single_test() {
    assert_eq!(vec!["IL_ONLY"], names(ComFlags::IL_ONLY));
    assert_eq!(vec!["REQUIRES_32BIT"], names(ComFlags::REQUIRES_32BIT));
    assert_eq!(vec!["IL_LIBRARY"], names(ComFlags::IL_LIBRARY));
    assert_eq!(
        vec!["STRONG_NAME_SIGNED"],
        names(ComFlags::STRONG_NAME_SIGNED)
    );
    assert_eq!(
        vec!["NATIVE_ENTRYPOINT"],
        names(ComFlags::NATIVE_ENTRYPOINT)
    );
    assert_eq!(vec!["TRACK_DEBUG_DATA"], names(ComFlags::TRACK_DEBUG_DATA));
}

#[test]
fn resolve_com_flags_multiple_test() {
    let resolved = names(ComFlags::from_bits_retain(0x00010005));

    assert_eq!(vec!["IL_ONLY", "IL_LIBRARY", "TRACK_DEBUG_DATA"], resolved);
}
