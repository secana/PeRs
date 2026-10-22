use std::sync::LazyLock;

use pers::net::MetadataTable;
use pers::pe::{ComFlags, DataDirectoryType};
use pers::{PeFile, Rva};
use uuid::Uuid;

use crate::common::load;

static DATA: LazyLock<Vec<u8>> = LazyLock::new(|| load("NetCoreConsole.dll"));

fn pe_file() -> PeFile<'static> {
    PeFile::parse(&DATA).unwrap()
}

#[test]
fn data_directory_com_descriptor_set() {
    let pe = pe_file();
    let data_directory = pe.data_directory(DataDirectoryType::ComDescriptor);

    assert_eq!(Rva(0x2008), data_directory.virtual_address());
    assert_eq!(0x48, data_directory.size());
}

#[test]
fn net_directory_parse_correct_values() {
    let pe = pe_file();
    let net_directory = pe.com_descriptor().unwrap().unwrap();

    assert_eq!(0x00000048, net_directory.cb());
    assert_eq!(0x0002, net_directory.major_runtime_version());
    assert_eq!(0x0005, net_directory.minor_runtime_version());
    assert_eq!(Rva(0x00003A38), net_directory.meta_data().virtual_address());
    assert_eq!(0x000056F8, net_directory.meta_data().size());
    assert_eq!(ComFlags::IL_ONLY, net_directory.flags() & ComFlags::IL_ONLY);
    assert_eq!(0x0600000C, net_directory.entry_point_token());
    assert_eq!(Rva(0x00000000), net_directory.resources().virtual_address());
    assert_eq!(0x00000000, net_directory.resources().size());
    assert_eq!(
        Rva(0x00000000),
        net_directory.strong_name_signature().virtual_address()
    );
    assert_eq!(0x00000000, net_directory.strong_name_signature().size());
    assert_eq!(
        Rva(0x00000000),
        net_directory.code_manager_table().virtual_address()
    );
    assert_eq!(0x00000000, net_directory.code_manager_table().size());
    assert_eq!(
        Rva(0x00000000),
        net_directory.v_table_fixups().virtual_address()
    );
    assert_eq!(0x00000000, net_directory.v_table_fixups().size());
    assert_eq!(
        Rva(0x00000000),
        net_directory.export_address_table_jumps().virtual_address()
    );
    assert_eq!(
        0x00000000,
        net_directory.export_address_table_jumps().size()
    );
    assert_eq!(
        Rva(0x00000000),
        net_directory.managed_native_header().virtual_address()
    );
    assert_eq!(0x00000000, net_directory.managed_native_header().size());
}

#[test]
fn meta_data_header_parse_correct_values() {
    let pe = pe_file();
    let meta_data_header = pe.metadata_header().unwrap().unwrap();

    assert_eq!(0x424A5342, meta_data_header.signature);
    assert_eq!(0x001, meta_data_header.major_version);
    assert_eq!(0x001, meta_data_header.minor_version);
    assert_eq!(0x00000000, meta_data_header.reserved);
    assert_eq!(0x0000000C, meta_data_header.version_length);
    assert_eq!("v4.0.30319", meta_data_header.version);
    assert_eq!(0x0000, meta_data_header.flags);
    assert_eq!(0x0005, meta_data_header.streams);
}

#[test]
fn meta_data_stream_tables_header_parse_correct_values() {
    let pe = pe_file();
    let tables_header = pe.metadata_tables_header().unwrap().unwrap();

    assert_eq!(0x00000000, tables_header.header.reserved1());
    assert_eq!(0x02, tables_header.header.major_version());
    assert_eq!(0x00, tables_header.header.minor_version());
    assert_eq!(0x01, tables_header.header.reserved2());
    assert_eq!(0x00001E0909A21F57, tables_header.header.mask_valid().bits());
    assert_eq!(0x000016003301FA00, tables_header.header.mask_sorted());
}

#[test]
fn meta_data_stream_us_parse_correct_values() {
    let pe = pe_file();
    let us: Vec<String> = pe
        .metadata_user_strings()
        .unwrap()
        .unwrap()
        .iter()
        .map(|s| s.unwrap().value)
        .collect();

    assert_eq!(51, us.len());
    assert_eq!("CandCMetaInformationService", us[0]);
    assert_eq!("Metainformation Proto3 Request for {0}.", us[44]);
    assert_eq!("ServiceEndpoints:Redis:CacheExpire:Minutes", us[50]);
}

#[test]
fn meta_data_stream_guid_parse_correct_values() {
    let pe = pe_file();
    let guid = pe.metadata_guids().unwrap().unwrap();

    assert_eq!(1, guid.len());
    assert_eq!(
        Uuid::parse_str("42f102e3-93ed-453b-bb95-d932c33520d4").unwrap(),
        guid.iter().next().unwrap()
    );
}

#[test]
fn meta_data_stream_blob_parse_correct_values() {
    let pe = pe_file();
    let blob = pe.metadata_blob().unwrap().unwrap().data();

    assert_eq!(0xC0C, blob.len());
    assert_eq!(0x00, blob[0]);
    assert_eq!(0x81, blob[0x400]);
    assert_eq!(0x70, blob[0xB70]);
}

#[test]
fn meta_data_tables_hdr_parse_correct_tables() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let table_definitions = hdr.table_infos().unwrap();

    assert_eq!(MetadataTable::Module, table_definitions[0].table);
    assert_eq!(0x1, table_definitions[0].row_count);
    assert_eq!(0x00, table_definitions[0].offset);
    assert_eq!(0x0A, table_definitions[0].bytes_per_row);

    assert_eq!(MetadataTable::AssemblyRef, table_definitions[35].table);
    assert_eq!(30, table_definitions[35].row_count);
    assert_eq!(0x1B50, table_definitions[35].offset);
    assert_eq!(20, table_definitions[35].bytes_per_row);
}

#[test]
fn meta_data_table_module() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let module = &hdr.tables().unwrap().module;

    assert_eq!(1, module.len());
    assert_eq!(0x0000, module[0].generation);
    assert_eq!(0x0F92, module[0].name);
    assert_eq!(0x0001, module[0].mvid);
    assert_eq!(0x0000, module[0].enc_id);
    assert_eq!(0x0000, module[0].enc_base_id);
}

#[test]
fn meta_data_table_type_ref() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let type_ref = &hdr.tables().unwrap().type_ref;
    let string_stream = pe.metadata_strings().unwrap().unwrap();

    assert_eq!(141, type_ref.len());

    assert_eq!(0x0006, type_ref[0].resolution_scope);
    assert_eq!(0x0CA3, type_ref[0].type_name);
    assert_eq!(0x182F, type_ref[0].type_namespace);
    assert_eq!(
        "CompilationRelaxationsAttribute",
        string_stream.get(type_ref[0].type_name).unwrap()
    );
    assert_eq!(
        "System.Runtime.CompilerServices",
        string_stream.get(type_ref[0].type_namespace).unwrap()
    );

    assert_eq!(0x000E, type_ref[22].resolution_scope);
    assert_eq!(0x17D1, type_ref[22].type_name);
    assert_eq!(0x0E57, type_ref[22].type_namespace);
    assert_eq!(
        "NormalizedUniformResourceLocator",
        string_stream.get(type_ref[22].type_name).unwrap()
    );
    assert_eq!(
        "GData.Messages.UrlProcessing",
        string_stream.get(type_ref[22].type_namespace).unwrap()
    );

    assert_eq!(0x0036, type_ref[140].resolution_scope);
    assert_eq!(0x0172, type_ref[140].type_name);
    assert_eq!(0x01E3, type_ref[140].type_namespace);
    assert_eq!(
        "Proto3Common`1",
        string_stream.get(type_ref[140].type_name).unwrap()
    );
    assert_eq!(
        "Jumpstart.Messages.Proto3",
        string_stream.get(type_ref[140].type_namespace).unwrap()
    );
}

#[test]
fn meta_data_table_type_def() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let type_def = &hdr.tables().unwrap().type_def;

    assert_eq!(45, type_def.len());

    assert_eq!(0x00000000, type_def[0].flags);
    assert_eq!(0x0229, type_def[0].name);
    assert_eq!(0x0000, type_def[0].namespace);
    assert_eq!(0x0000, type_def[0].extends);
    assert_eq!(0x0001, type_def[0].field_list);
    assert_eq!(0x0001, type_def[0].method_list);

    assert_eq!(0x00100182, type_def[44].flags);
    assert_eq!(0x0AA6, type_def[44].name);
    assert_eq!(0x0000, type_def[44].namespace);
    assert_eq!(0x0035, type_def[44].extends);
    assert_eq!(0x005A, type_def[44].field_list);
    assert_eq!(0x006E, type_def[44].method_list);
}

#[test]
fn meta_data_table_field() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let field = &hdr.tables().unwrap().field;

    assert_eq!(92, field.len());

    assert_eq!(0x8056, field[0].flags);
    assert_eq!(0x049D, field[0].name);
    assert_eq!(0x088C, field[0].signature);

    assert_eq!(0x0031, field[91].flags);
    assert_eq!(0x0727, field[91].name);
    assert_eq!(0x088C, field[91].signature);
}

#[test]
fn meta_data_table_method_def() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let method_def = &hdr.tables().unwrap().method_def;

    assert_eq!(113, method_def.len());

    assert_eq!(0x0000, method_def[0].rva);
    assert_eq!(0x0000, method_def[0].impl_flags);
    assert_eq!(0x05C6, method_def[0].flags);
    assert_eq!(0x0F24, method_def[0].name);
    assert_eq!(0x09D3, method_def[0].signature);
    assert_eq!(0x0001, method_def[0].param_list);

    assert_eq!(0x39E0, method_def[112].rva);
    assert_eq!(0x0000, method_def[112].impl_flags);
    assert_eq!(0x1891, method_def[112].flags);
    assert_eq!(0x1806, method_def[112].name);
    assert_eq!(0x0A15, method_def[112].signature);
    assert_eq!(0x007E, method_def[112].param_list);
}

#[test]
fn meta_data_table_param() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let param = &hdr.tables().unwrap().param;

    assert_eq!(125, param.len());

    assert_eq!(0x0000, param[0].flags);
    assert_eq!(0x0001, param[0].sequence);
    assert_eq!(0x1085, param[0].name);
    assert_eq!(
        "fqhn",
        pe.metadata_strings()
            .unwrap()
            .unwrap()
            .get(param[0].name)
            .unwrap()
    );

    assert_eq!(0x0000, param[1].flags);
    assert_eq!(0x0001, param[1].sequence);
    assert_eq!(0x148E, param[1].name);
    assert_eq!(
        "logger",
        pe.metadata_strings()
            .unwrap()
            .unwrap()
            .get(param[1].name)
            .unwrap()
    );

    assert_eq!(0x0000, param[124].flags);
    assert_eq!(0x0001, param[124].sequence);
    assert_eq!(0x0D4C, param[124].name);
    assert_eq!(
        "value",
        pe.metadata_strings()
            .unwrap()
            .unwrap()
            .get(param[124].name)
            .unwrap()
    );
}

#[test]
fn meta_data_table_interface_impl() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let interface_impl = &hdr.tables().unwrap().interface_impl;

    assert_eq!(3, interface_impl.len());

    assert_eq!(0x0005, interface_impl[0].class);
    assert_eq!(0x004D, interface_impl[0].interface);

    assert_eq!(0x0006, interface_impl[1].class);
    assert_eq!(0x000C, interface_impl[1].interface);

    assert_eq!(0x0019, interface_impl[2].class);
    assert_eq!(0x0068, interface_impl[2].interface);
}

#[test]
fn meta_data_table_member_ref() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let member_ref = &hdr.tables().unwrap().member_ref;

    assert_eq!(216, member_ref.len());

    assert_eq!(0x0009, member_ref[0].class);
    assert_eq!(0x1800, member_ref[0].name);
    assert_eq!(0x0001, member_ref[0].signature);

    assert_eq!(0x0409, member_ref[215].class);
    assert_eq!(0x01A8, member_ref[215].name);
    assert_eq!(0x07D7, member_ref[215].signature);
}

#[test]
fn meta_data_table_constant() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let constant = &hdr.tables().unwrap().constant;

    assert_eq!(38, constant.len());

    assert_eq!(0x08, constant[0].r#type);
    assert_eq!(0x0004, constant[0].parent);
    assert_eq!(0x0800, constant[0].value);

    assert_eq!(0x12, constant[37].r#type);
    assert_eq!(0x0195, constant[37].parent);
    assert_eq!(0x0887, constant[37].value);
}

#[test]
fn meta_data_table_custom_attribute() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let custom_attribute = &hdr.tables().unwrap().custom_attribute;

    assert_eq!(97, custom_attribute.len());

    assert_eq!(0x002E, custom_attribute[0].parent);
    assert_eq!(0x000B, custom_attribute[0].r#type);
    assert_eq!(0x0B31, custom_attribute[0].value);

    assert_eq!(0x0F44, custom_attribute[96].parent);
    assert_eq!(0x0073, custom_attribute[96].r#type);
    assert_eq!(0x0BFD, custom_attribute[96].value);
}

#[test]
fn meta_data_table_field_marshall() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let field_marshall = &hdr.tables().unwrap().field_marshal;

    assert!(field_marshall.is_empty());
}

#[test]
fn meta_data_table_decl_security() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let decl_security = &hdr.tables().unwrap().decl_security;

    assert!(decl_security.is_empty());
}

#[test]
fn meta_data_table_class_layout() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let class_layout = &hdr.tables().unwrap().class_layout;

    assert!(class_layout.is_empty());
}

#[test]
fn meta_data_table_field_layout() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let field_layout = &hdr.tables().unwrap().field_layout;

    assert!(field_layout.is_empty());
}

#[test]
fn meta_data_table_stand_alone_sig() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let stand_alone_sig = &hdr.tables().unwrap().stand_alone_sig;

    assert_eq!(30, stand_alone_sig.len());

    assert_eq!(0x0027, stand_alone_sig[0].signature);

    assert_eq!(0x07C4, stand_alone_sig[29].signature);
}

#[test]
fn meta_data_table_event_map() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let event_map = &hdr.tables().unwrap().event_map;

    assert!(event_map.is_empty());
}

#[test]
fn meta_data_table_event() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let ev = &hdr.tables().unwrap().event;

    assert!(ev.is_empty());
}

#[test]
fn meta_data_table_property_map() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let property_map = &hdr.tables().unwrap().property_map;

    assert_eq!(6, property_map.len());

    assert_eq!(0x0005, property_map[0].parent);
    assert_eq!(0x0001, property_map[0].property_list);

    assert_eq!(0x002D, property_map[5].parent);
    assert_eq!(0x0017, property_map[5].property_list);
}

#[test]
fn meta_data_table_property() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let property = &hdr.tables().unwrap().property;

    assert_eq!(25, property.len());

    assert_eq!(0x0000, property[0].flags);
    assert_eq!(0x0521, property[0].name);
    assert_eq!(0x0B1B, property[0].r#type);

    assert_eq!(0x0000, property[24].flags);
    assert_eq!(0x18BB, property[24].name);
    assert_eq!(0x0B2D, property[24].r#type);
}

#[test]
fn meta_data_table_method_semantics() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let method_semantics = &hdr.tables().unwrap().method_semantics;

    assert_eq!(27, method_semantics.len());

    assert_eq!(0x0002, method_semantics[0].semantics);
    assert_eq!(0x0002, method_semantics[0].method);
    assert_eq!(0x0003, method_semantics[0].association);

    assert_eq!(0x0002, method_semantics[26].semantics);
    assert_eq!(0x0070, method_semantics[26].method);
    assert_eq!(0x00033, method_semantics[26].association);
}

#[test]
fn meta_data_table_method_impl() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let method_impl = &hdr.tables().unwrap().method_impl;

    assert!(method_impl.is_empty());
}

#[test]
fn meta_data_table_module_ref() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let module_ref = &hdr.tables().unwrap().module_ref;

    assert!(module_ref.is_empty());
}

#[test]
fn meta_data_table_type_spec() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let type_spec = &hdr.tables().unwrap().type_spec;

    assert_eq!(43, type_spec.len());

    assert_eq!(0x001B, type_spec[0].signature);

    assert_eq!(0x07B5, type_spec[42].signature);
}

#[test]
fn meta_data_table_field_rva() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let field_rva = &hdr.tables().unwrap().field_rva;

    assert!(field_rva.is_empty());
}

#[test]
fn meta_data_table_assembly() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let assembly = &hdr.tables().unwrap().assembly;

    assert_eq!(1, assembly.len());

    assert_eq!(0x00008004, assembly[0].hash_alg_id);
    assert_eq!(0x0001, assembly[0].major_version);
    assert_eq!(0x0009, assembly[0].minor_version);
    assert_eq!(0x0007, assembly[0].build_number);
    assert_eq!(0x0000, assembly[0].revision_number);
    assert_eq!(0x00000000, assembly[0].flags);
    assert_eq!(0x0000, assembly[0].public_key);
    assert_eq!(0x08CF, assembly[0].name);
    assert_eq!(0x0000, assembly[0].culture);
}

#[test]
fn meta_data_table_assembly_processor() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let assembly_processor = &hdr.tables().unwrap().assembly_processor;

    assert!(assembly_processor.is_empty());
}

#[test]
fn meta_data_table_assembly_os() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let assembly_os = &hdr.tables().unwrap().assembly_os;

    assert!(assembly_os.is_empty());
}

#[test]
fn meta_data_table_assembly_ref() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let assembly_ref = &hdr.tables().unwrap().assembly_ref;

    assert_eq!(30, assembly_ref.len());

    assert_eq!(0x0004, assembly_ref[0].major_version);
    assert_eq!(0x0002, assembly_ref[0].minor_version);
    assert_eq!(0x0000, assembly_ref[0].build_number);
    assert_eq!(0x0000, assembly_ref[0].revision_number);
    assert_eq!(0x00000000, assembly_ref[0].flags);
    assert_eq!(0x07DC, assembly_ref[0].public_key_or_token);
    assert_eq!(0x0A33, assembly_ref[0].name);
    assert_eq!(0x0000, assembly_ref[0].culture);
    assert_eq!(0x0000, assembly_ref[0].hash_value);

    assert_eq!(0x0001, assembly_ref[29].major_version);
    assert_eq!(0x0001, assembly_ref[29].minor_version);
    assert_eq!(0x0002, assembly_ref[29].build_number);
    assert_eq!(0x0000, assembly_ref[29].revision_number);
    assert_eq!(0x00000000, assembly_ref[29].flags);
    assert_eq!(0x07E5, assembly_ref[29].public_key_or_token);
    assert_eq!(0x1A98, assembly_ref[29].name);
    assert_eq!(0x0000, assembly_ref[29].culture);
    assert_eq!(0x0000, assembly_ref[29].hash_value);
}

#[test]
fn meta_data_table_assembly_ref_processor() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let assembly_ref_processor = &hdr.tables().unwrap().assembly_ref_processor;

    assert!(assembly_ref_processor.is_empty());
}

#[test]
fn meta_data_table_assembly_ref_os() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let assembly_ref_os = &hdr.tables().unwrap().assembly_ref_os;

    assert!(assembly_ref_os.is_empty());
}

#[test]
fn meta_data_table_file() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let file = &hdr.tables().unwrap().file;

    assert!(file.is_empty());
}

#[test]
fn meta_data_table_exported_type() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let exported_type = &hdr.tables().unwrap().exported_type;

    assert!(exported_type.is_empty());
}

#[test]
fn meta_data_table_manifest_resource() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let manifest_resource = &hdr.tables().unwrap().manifest_resource;

    assert!(manifest_resource.is_empty());
}

#[test]
fn meta_data_table_nested_class() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let nested_class = &hdr.tables().unwrap().nested_class;

    assert_eq!(19, nested_class.len());

    assert_eq!(0x001B, nested_class[0].nested_class_type);
    assert_eq!(0x0002, nested_class[0].enclosing_class_type);

    assert_eq!(0x002D, nested_class[18].nested_class_type);
    assert_eq!(0x002C, nested_class[18].enclosing_class_type);
}

#[test]
fn meta_data_table_generic_param() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let generic_param = &hdr.tables().unwrap().generic_param;

    assert_eq!(1, generic_param.len());

    assert_eq!(0x0000, generic_param[0].number);
    assert_eq!(0x0010, generic_param[0].flags);
    assert_eq!(0x0047, generic_param[0].owner);
    assert_eq!(0x0835, generic_param[0].name);
}

#[test]
fn meta_data_table_generic_param_constraint() {
    let pe = pe_file();
    let hdr = pe.metadata_tables_header().unwrap().unwrap();
    let generic_param_constraint = &hdr.tables().unwrap().generic_param_constraint;

    assert_eq!(1, generic_param_constraint.len());
    assert_eq!(0x0001, generic_param_constraint[0].owner);
    // PeNet does not read the column and reports 0. The value is TypeSpec row 1.
    assert_eq!(0x0006, generic_param_constraint[0].constraint);
}

#[test]
fn net_guid_module_version_id() {
    let pe = pe_file();
    let mvids = pe.clr_module_version_ids().unwrap().unwrap();

    assert_eq!(1, mvids.len());
    assert_eq!(
        Uuid::parse_str("42f102e3-93ed-453b-bb95-d932c33520d4").unwrap(),
        mvids[0]
    );
}

#[test]
fn net_guid_com_type_lib_id() {
    let pe = pe_file();

    assert!(pe.clr_com_type_lib_id().unwrap().is_none());
}

#[cfg(feature = "authenticode")]
#[test]
fn is_signature_valid() {
    assert!(!pe_file().has_valid_signature());
}
