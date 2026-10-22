//! The rows of the metadata tables in the `#~` stream.

use alloc::vec::Vec;

use super::coded_index::{CodedIndex, IndexSizes, MetadataTable};
use super::tables_header::{HeapSizes, TableInfo};
use crate::bytes::Bytes;
use crate::error::Result;

/// The kind of a column, which decides its width.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Column {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    Table(MetadataTable),
    Coded(CodedIndex),
}

/// Column widths of a tables stream.
#[derive(Debug, Clone)]
pub(crate) struct ColumnSizes {
    pub heap_sizes: HeapSizes,
    pub index_sizes: IndexSizes,
}

impl ColumnSizes {
    fn size(&self, column: Column) -> usize {
        match column {
            Column::U16 => 2,
            Column::U32 => 4,
            Column::Str => self.heap_sizes.string_index_size(),
            Column::Guid => self.heap_sizes.guid_index_size(),
            Column::Blob => self.heap_sizes.blob_index_size(),
            Column::Table(table) => self.index_sizes.table(table),
            Column::Coded(index) => self.index_sizes.coded(index),
        }
    }

    /// Size of a row of `table`, 0 for tables without known columns.
    pub fn row_size(&self, table: MetadataTable) -> usize {
        columns(table).iter().map(|&c| self.size(c)).sum()
    }
}

/// Reads the columns of a row one after another.
struct RowReader<'r> {
    row: &'r [u8],
    position: usize,
    sizes: &'r ColumnSizes,
}

impl RowReader<'_> {
    fn read<T: FromColumn>(&mut self, column: Column) -> Result<T> {
        let size = self.sizes.size(column);
        let bytes = Bytes(self.row);
        let value = match size {
            2 => u32::from(bytes.u16(self.position)?),
            _ => bytes.u32(self.position)?,
        };
        self.position += size;
        Ok(T::from_column(value))
    }
}

/// Conversion of a column value to the field type. Narrower fields keep the low bytes.
trait FromColumn {
    fn from_column(value: u32) -> Self;
}

impl FromColumn for u8 {
    fn from_column(value: u32) -> Self {
        value as u8
    }
}

impl FromColumn for u16 {
    fn from_column(value: u32) -> Self {
        value as u16
    }
}

impl FromColumn for u32 {
    fn from_column(value: u32) -> Self {
        value
    }
}

/// Parses the rows of the tables, which follow each other in table number order.
pub(crate) struct TableParser<'p> {
    /// The table data after the row counts and the extra data.
    pub data: &'p [u8],
    pub infos: &'p [TableInfo],
    pub sizes: &'p ColumnSizes,
}

impl TableParser<'_> {
    fn rows<R>(
        &self,
        table: MetadataTable,
        parse: fn(&mut RowReader<'_>) -> Result<R>,
    ) -> Result<Vec<R>> {
        let Some(info) = self.infos.get(table.value() as usize) else {
            return Ok(Vec::new());
        };
        let row_size = info.bytes_per_row as usize;
        if row_size == 0 {
            return Ok(Vec::new());
        }
        let bytes = Bytes(self.data).slice(
            info.offset as usize,
            row_size.saturating_mul(info.row_count as usize),
        )?;
        bytes
            .chunks_exact(row_size)
            .map(|row| {
                parse(&mut RowReader {
                    row,
                    position: 0,
                    sizes: self.sizes,
                })
            })
            .collect()
    }
}

/// Define the row structures, the [`Tables`] collection and the columns of every table.
macro_rules! tables {
    ($(
        $(#[$meta:meta])*
        $field:ident: $row:ident = $table:ident { $($(#[$column_meta:meta])* $column:ident: $ty:ty = $kind:expr),* $(,)? }
    )*) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[non_exhaustive]
            pub struct $row {
                $($(#[$column_meta])* pub $column: $ty,)*
            }

            impl $row {
                const COLUMNS: &[Column] = &[$($kind),*];

                fn parse(r: &mut RowReader<'_>) -> Result<Self> {
                    Ok(Self { $($column: r.read($kind)?,)* })
                }
            }
        )*

        /// All parsed metadata tables. Tables that are not present are empty.
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        #[non_exhaustive]
        pub struct Tables {
            $(pub $field: Vec<$row>,)*
        }

        impl Tables {
            pub(crate) fn parse(parser: &TableParser<'_>) -> Result<Self> {
                Ok(Self { $($field: parser.rows(MetadataTable::$table, $row::parse)?,)* })
            }
        }

        /// The columns of a table, empty for tables without known layout.
        fn columns(table: MetadataTable) -> &'static [Column] {
            match table {
                $(MetadataTable::$table => $row::COLUMNS,)*
                _ => &[],
            }
        }
    };
}

use CodedIndex as C;
use Column::{Blob, Coded, Guid, Str, Table, U16, U32};
use MetadataTable as T;

tables! {
    module: Module = Module {
        generation: u16 = U16,
        name: u32 = Str,
        mvid: u32 = Guid,
        enc_id: u32 = Guid,
        enc_base_id: u32 = Guid,
    }
    type_ref: TypeRef = TypeRef {
        resolution_scope: u32 = Coded(C::ResolutionScope),
        type_name: u32 = Str,
        type_namespace: u32 = Str,
    }
    type_def: TypeDef = TypeDef {
        flags: u32 = U32,
        name: u32 = Str,
        namespace: u32 = Str,
        extends: u32 = Coded(C::TypeDefOrRef),
        field_list: u32 = Table(T::Field),
        method_list: u32 = Table(T::MethodDef),
    }
    field: Field = Field {
        flags: u16 = U16,
        name: u32 = Str,
        signature: u32 = Blob,
    }
    method_def: MethodDef = MethodDef {
        rva: u32 = U32,
        impl_flags: u16 = U16,
        flags: u16 = U16,
        name: u32 = Str,
        signature: u32 = Blob,
        param_list: u32 = Table(T::Param),
    }
    param: Param = Param {
        flags: u16 = U16,
        sequence: u16 = U16,
        name: u32 = Str,
    }
    interface_impl: InterfaceImpl = InterfaceImpl {
        class: u32 = Table(T::TypeDef),
        interface: u32 = Coded(C::TypeDefOrRef),
    }
    member_ref: MemberRef = MemberRef {
        class: u32 = Coded(C::MemberRefParent),
        name: u32 = Str,
        signature: u32 = Blob,
    }
    /// Row of the Constant table. `type` is a single byte followed by one padding byte.
    constant: Constant = Constant {
        r#type: u8 = U16,
        parent: u32 = Coded(C::HasConstant),
        value: u32 = Blob,
    }
    custom_attribute: CustomAttribute = CustomAttribute {
        parent: u32 = Coded(C::HasCustomAttribute),
        r#type: u32 = Coded(C::CustomAttributeType),
        value: u32 = Blob,
    }
    field_marshal: FieldMarshal = FieldMarshal {
        parent: u32 = Coded(C::HasFieldMarshal),
        native_type: u32 = Blob,
    }
    decl_security: DeclSecurity = DeclSecurity {
        action: u16 = U16,
        parent: u32 = Coded(C::HasDeclSecurity),
        permission_set: u32 = Blob,
    }
    class_layout: ClassLayout = ClassLayout {
        packing_size: u16 = U16,
        class_size: u32 = U32,
        parent: u32 = Table(T::TypeDef),
    }
    field_layout: FieldLayout = FieldLayout {
        offset_value: u32 = U32,
        field: u32 = Table(T::Field),
    }
    stand_alone_sig: StandAloneSig = StandAloneSig {
        signature: u32 = Blob,
    }
    event_map: EventMap = EventMap {
        parent: u32 = Table(T::TypeDef),
        event_list: u32 = Table(T::Event),
    }
    event: Event = Event {
        event_flags: u16 = U16,
        name: u32 = Str,
        event_type: u32 = Coded(C::TypeDefOrRef),
    }
    property_map: PropertyMap = PropertyMap {
        parent: u32 = Table(T::TypeDef),
        property_list: u32 = Table(T::Property),
    }
    property: Property = Property {
        flags: u16 = U16,
        name: u32 = Str,
        r#type: u32 = Blob,
    }
    method_semantics: MethodSemantics = MethodSemantics {
        semantics: u16 = U16,
        method: u32 = Table(T::MethodDef),
        association: u32 = Coded(C::HasSemantics),
    }
    method_impl: MethodImpl = MethodImpl {
        class: u32 = Table(T::TypeDef),
        method_body: u32 = Coded(C::MethodDefOrRef),
        method_declaration: u32 = Coded(C::MethodDefOrRef),
    }
    module_ref: ModuleRef = ModuleRef {
        name: u32 = Str,
    }
    type_spec: TypeSpec = TypeSpec {
        signature: u32 = Blob,
    }
    impl_map: ImplMap = ImplMap {
        mapping_flags: u16 = U16,
        member_forwarded: u32 = Coded(C::MemberForwarded),
        import_name: u32 = Str,
        import_scope: u32 = Table(T::ModuleRef),
    }
    field_rva: FieldRva = FieldRva {
        rva: u32 = U32,
        field: u32 = Table(T::Field),
    }
    assembly: Assembly = Assembly {
        hash_alg_id: u32 = U32,
        major_version: u16 = U16,
        minor_version: u16 = U16,
        build_number: u16 = U16,
        revision_number: u16 = U16,
        flags: u32 = U32,
        public_key: u32 = Blob,
        name: u32 = Str,
        culture: u32 = Str,
    }
    assembly_processor: AssemblyProcessor = AssemblyProcessor {
        processor: u32 = U32,
    }
    assembly_os: AssemblyOs = AssemblyOS {
        os_platform_id: u32 = U32,
        os_major_version: u32 = U32,
        os_minor_version: u32 = U32,
    }
    assembly_ref: AssemblyRef = AssemblyRef {
        major_version: u16 = U16,
        minor_version: u16 = U16,
        build_number: u16 = U16,
        revision_number: u16 = U16,
        flags: u32 = U32,
        public_key_or_token: u32 = Blob,
        name: u32 = Str,
        culture: u32 = Str,
        hash_value: u32 = Blob,
    }
    assembly_ref_processor: AssemblyRefProcessor = AssemblyRefProcessor {
        processor: u32 = U32,
        assembly_ref: u32 = Table(T::AssemblyRef),
    }
    assembly_ref_os: AssemblyRefOs = AssemblyRefOS {
        os_platform_id: u32 = U32,
        os_major_version: u32 = U32,
        os_minor_version: u32 = U32,
        assembly_ref: u32 = Table(T::AssemblyRef),
    }
    file: File = File {
        flags: u32 = U32,
        name: u32 = Str,
        hash_value: u32 = Blob,
    }
    exported_type: ExportedType = ExportedType {
        flags: u32 = U32,
        /// A hint into the TypeDef table of the file that defines the type, always 4 bytes.
        type_def_id: u32 = U32,
        type_name: u32 = Str,
        type_namespace: u32 = Str,
        implementation: u32 = Coded(C::Implementation),
    }
    manifest_resource: ManifestResource = ManifestResource {
        offset_value: u32 = U32,
        flags: u32 = U32,
        name: u32 = Str,
        implementation: u32 = Coded(C::Implementation),
    }
    nested_class: NestedClass = NestedClass {
        nested_class_type: u32 = Table(T::TypeDef),
        enclosing_class_type: u32 = Table(T::TypeDef),
    }
    generic_param: GenericParam = GenericParam {
        number: u16 = U16,
        flags: u16 = U16,
        owner: u32 = Coded(C::TypeOrMethodDef),
        name: u32 = Str,
    }
    method_spec: MethodSpec = MethodSpec {
        method: u32 = Coded(C::MethodDefOrRef),
        instantiation: u32 = Blob,
    }
    generic_param_constraint: GenericParamConstraint = GenericParamConstraint {
        owner: u32 = Table(T::GenericParam),
        constraint: u32 = Coded(C::TypeDefOrRef),
    }
}
