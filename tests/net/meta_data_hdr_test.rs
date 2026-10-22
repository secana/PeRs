use crate::common::raw_dot_net_structures::RAW_META_DATA_HEADER;
use pers::net::{MaskValid, MetadataHeader, MetadataTable};

#[test]
fn meta_data_hdr_constructor_works_test() {
    let h = MetadataHeader::parse(RAW_META_DATA_HEADER, 2).unwrap();
    assert_eq!(0x55443322, h.signature);
    assert_eq!(0x7766, h.major_version);
    assert_eq!(0x9988, h.minor_version);
    assert_eq!(0xddccbbaa, h.reserved);
    assert_eq!(0x0000000C, h.version_length);
    assert_eq!("v4.0.30319", h.version);
    assert_eq!(0x2211, h.flags);
    assert_eq!(0x0002, h.streams);

    let streams = &h.stream_headers;
    assert_eq!(2, streams.len());
    assert_eq!(0x6C, streams[0].stream_offset);
    assert_eq!(0x1804, streams[0].size);
    assert_eq!("#~", streams[0].name);
    assert_eq!(0x1870, streams[1].stream_offset);
    assert_eq!(0x1468, streams[1].size);
    assert_eq!("#Strings", streams[1].name);
}

#[test]
fn resolve_mask_valid_single_test() {
    use MaskValid as M;
    let first = |m: M| m.tables().next().unwrap().to_string();
    assert_eq!("Module", first(M::MODULE));
    assert_eq!("TypeRef", first(M::TYPE_REF));
    assert_eq!("TypeDef", first(M::TYPE_DEF));
    assert_eq!("Field", first(M::FIELD));
    assert_eq!("MethodDef", first(M::METHOD_DEF));
    assert_eq!("Param", first(M::PARAM));
    assert_eq!("InterfaceImpl", first(M::INTERFACE_IMPL));
    assert_eq!("MemberRef", first(M::MEMBER_REF));
    assert_eq!("Constant", first(M::CONSTANT));
    assert_eq!("CustomAttribute", first(M::CUSTOM_ATTRIBUTE));
    assert_eq!("FieldMarshal", first(M::FIELD_MARSHAL));
    assert_eq!("DeclSecurity", first(M::DECL_SECURITY));
    assert_eq!("ClassLayout", first(M::CLASS_LAYOUT));
    assert_eq!("FieldLayout", first(M::FIELD_LAYOUT));
    assert_eq!("StandAloneSig", first(M::STAND_ALONE_SIG));
    assert_eq!("EventMap", first(M::EVENT_MAP));
    assert_eq!("Event", first(M::EVENT));
    assert_eq!("PropertyMap", first(M::PROPERTY_MAP));
    assert_eq!("Property", first(M::PROPERTY));
    assert_eq!("MethodSemantics", first(M::METHOD_SEMANTICS));
    assert_eq!("MethodImpl", first(M::METHOD_IMPL));
    assert_eq!("ModuleRef", first(M::MODULE_REF));
    assert_eq!("TypeSpec", first(M::TYPE_SPEC));
    assert_eq!("ImplMap", first(M::IMPL_MAP));
    assert_eq!("FieldRva", first(M::FIELD_RVA));
    assert_eq!("Assembly", first(M::ASSEMBLY));
    assert_eq!("AssemblyProcessor", first(M::ASSEMBLY_PROCESSOR));
    assert_eq!("AssemblyOS", first(M::ASSEMBLY_OS));
    assert_eq!("AssemblyRef", first(M::ASSEMBLY_REF));
    assert_eq!("AssemblyRefProcessor", first(M::ASSEMBLY_REF_PROCESSOR));
    assert_eq!("AssemblyRefOS", first(M::ASSEMBLY_REF_OS));
    assert_eq!("File", first(M::FILE));
    assert_eq!("ExportedType", first(M::EXPORTED_TYPE));
    assert_eq!("ManifestResource", first(M::MANIFEST_RESOURCE));
    assert_eq!("NestedClass", first(M::NESTED_CLASS));
    assert_eq!("GenericParam", first(M::GENERIC_PARAM));
    assert_eq!("GenericParamConstraint", first(M::GENERIC_PARAM_CONSTRAINT));
}

#[test]
fn resolve_mask_valid_multiple_test() {
    let tables: Vec<MetadataTable> = MaskValid::from_bits_retain(0x00000A0909A21F57)
        .tables()
        .collect();

    assert_eq!(19, tables.len());
    for name in [
        "Module",
        "TypeRef",
        "TypeDef",
        "Field",
        "MethodDef",
        "Param",
        "InterfaceImpl",
        "MemberRef",
        "Constant",
        "CustomAttribute",
        "StandAloneSig",
        "PropertyMap",
        "Property",
        "MethodSemantics",
        "TypeSpec",
        "Assembly",
        "AssemblyRef",
        "NestedClass",
        "MethodSpec",
    ] {
        assert!(tables.iter().any(|t| t.name() == Some(name)), "{name}");
    }
}
