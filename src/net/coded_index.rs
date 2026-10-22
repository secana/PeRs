pe_enum! {
    /// The number of a metadata table.
    pub enum MetadataTable: u8 {
        Module = 0x00,
        TypeRef = 0x01,
        TypeDef = 0x02,
        Field = 0x04,
        MethodDef = 0x06,
        Param = 0x08,
        InterfaceImpl = 0x09,
        MemberRef = 0x0A,
        Constant = 0x0B,
        CustomAttribute = 0x0C,
        FieldMarshal = 0x0D,
        DeclSecurity = 0x0E,
        ClassLayout = 0x0F,
        FieldLayout = 0x10,
        StandAloneSig = 0x11,
        EventMap = 0x12,
        Event = 0x14,
        PropertyMap = 0x15,
        Property = 0x17,
        MethodSemantics = 0x18,
        MethodImpl = 0x19,
        ModuleRef = 0x1A,
        TypeSpec = 0x1B,
        ImplMap = 0x1C,
        FieldRva = 0x1D,
        Assembly = 0x20,
        AssemblyProcessor = 0x21,
        AssemblyOS = 0x22,
        AssemblyRef = 0x23,
        AssemblyRefProcessor = 0x24,
        AssemblyRefOS = 0x25,
        File = 0x26,
        ExportedType = 0x27,
        ManifestResource = 0x28,
        NestedClass = 0x29,
        GenericParam = 0x2A,
        MethodSpec = 0x2B,
        GenericParamConstraint = 0x2C,
    }
}

/// Number of table numbers in the tables stream header.
pub(crate) const TABLE_COUNT: usize = 64;

/// A coded index: a row index into one of several tables, tagged in the low bits.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CodedIndex {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

impl CodedIndex {
    /// The tables the index can point to, in tag order. `None` marks unused tags.
    pub fn tables(self) -> &'static [Option<MetadataTable>] {
        use MetadataTable as T;
        match self {
            Self::TypeDefOrRef => &[Some(T::TypeDef), Some(T::TypeRef), Some(T::TypeSpec)],
            Self::HasConstant => &[Some(T::Field), Some(T::Param), Some(T::Property)],
            Self::HasCustomAttribute => &[
                Some(T::MethodDef),
                Some(T::Field),
                Some(T::TypeRef),
                Some(T::TypeDef),
                Some(T::Param),
                Some(T::InterfaceImpl),
                Some(T::MemberRef),
                Some(T::Module),
                Some(T::DeclSecurity),
                Some(T::Property),
                Some(T::Event),
                Some(T::StandAloneSig),
                Some(T::ModuleRef),
                Some(T::TypeSpec),
                Some(T::Assembly),
                Some(T::AssemblyRef),
                Some(T::File),
                Some(T::ExportedType),
                Some(T::ManifestResource),
                Some(T::GenericParam),
                Some(T::GenericParamConstraint),
                Some(T::MethodSpec),
            ],
            Self::HasFieldMarshal => &[Some(T::Field), Some(T::Param)],
            Self::HasDeclSecurity => &[Some(T::TypeDef), Some(T::MethodDef), Some(T::Assembly)],
            Self::MemberRefParent => &[
                Some(T::TypeDef),
                Some(T::TypeRef),
                Some(T::ModuleRef),
                Some(T::MethodDef),
                Some(T::TypeSpec),
            ],
            Self::HasSemantics => &[Some(T::Event), Some(T::Property)],
            Self::MethodDefOrRef => &[Some(T::MethodDef), Some(T::MemberRef)],
            Self::MemberForwarded => &[Some(T::Field), Some(T::MethodDef)],
            Self::Implementation => &[Some(T::File), Some(T::AssemblyRef), Some(T::ExportedType)],
            Self::CustomAttributeType => {
                &[None, None, Some(T::MethodDef), Some(T::MemberRef), None]
            }
            Self::ResolutionScope => &[
                Some(T::Module),
                Some(T::ModuleRef),
                Some(T::AssemblyRef),
                Some(T::TypeRef),
            ],
            Self::TypeOrMethodDef => &[Some(T::TypeDef), Some(T::MethodDef)],
        }
    }

    /// Number of tag bits.
    pub fn tag_bits(self) -> u32 {
        usize::BITS - (self.tables().len() - 1).leading_zeros()
    }

    /// Split a coded index value into the table and the 1 based row. `None` for unused tags.
    pub fn decode(self, value: u32) -> Option<(MetadataTable, u32)> {
        let bits = self.tag_bits();
        let tag = (value & ((1 << bits) - 1)) as usize;
        let table = (*self.tables().get(tag)?)?;
        Some((table, value >> bits))
    }
}

/// Width in bytes of the table indices, derived from the row counts of the tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexSizes {
    row_counts: [u32; TABLE_COUNT],
}

impl IndexSizes {
    pub fn new(row_counts: [u32; TABLE_COUNT]) -> Self {
        Self { row_counts }
    }

    pub fn row_count(&self, table: MetadataTable) -> u32 {
        self.row_counts
            .get(table.value() as usize)
            .copied()
            .unwrap_or(0)
    }

    /// Size of an index into a single table.
    pub fn table(&self, table: MetadataTable) -> usize {
        Self::width(self.row_count(table), 0)
    }

    pub fn coded(&self, index: CodedIndex) -> usize {
        let max_rows = index
            .tables()
            .iter()
            .flatten()
            .map(|&t| self.row_count(t))
            .max()
            .unwrap_or(0);
        Self::width(max_rows, index.tag_bits())
    }

    fn width(rows: u32, tag_bits: u32) -> usize {
        if u64::from(rows) < 1u64 << (16 - tag_bits) {
            2
        } else {
            4
        }
    }
}
