use alloc::vec::Vec;

use zerocopy::little_endian::{U32, U64};

use super::coded_index::{IndexSizes, MetadataTable, TABLE_COUNT};
use super::file_offset;
use super::tables::{ColumnSizes, TableParser, Tables};
use crate::address::FileOffset;
use crate::bytes::Bytes;
use crate::error::{Result, malformed};

pe_struct! {
    /// The fixed part of the `#~` (tables) stream header.
    pub struct TablesStreamHeader {
        reserved1: U32 => u32,
        major_version: u8 => u8,
        minor_version: u8 => u8,
        heap_sizes: u8 => HeapSizes,
        reserved2: u8 => u8,
        /// The tables which are present.
        mask_valid: U64 => MaskValid,
        /// The tables which are sorted.
        mask_sorted: U64 => u64,
    }
}

bitflags::bitflags! {
    /// The `HeapSizes` byte of the tables stream header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct HeapSizes: u8 {
        /// Indices into `#Strings` are 4 bytes wide.
        const STRINGS = 0x01;
        /// Indices into `#GUID` are 4 bytes wide.
        const GUID = 0x02;
        /// Indices into `#Blob` are 4 bytes wide.
        const BLOB = 0x04;
        /// 4 bytes of undocumented extra data follow the row counts.
        const EXTRA_DATA = 0x40;
    }
}

impl From<u8> for HeapSizes {
    fn from(bits: u8) -> Self {
        Self::from_bits_retain(bits)
    }
}

impl HeapSizes {
    pub fn string_index_size(self) -> usize {
        self.index_size(Self::STRINGS)
    }

    pub fn guid_index_size(self) -> usize {
        self.index_size(Self::GUID)
    }

    pub fn blob_index_size(self) -> usize {
        self.index_size(Self::BLOB)
    }

    pub fn has_extra_data(self) -> bool {
        self.contains(Self::EXTRA_DATA)
    }

    fn index_size(self, flag: Self) -> usize {
        if self.contains(flag) { 4 } else { 2 }
    }
}

bitflags::bitflags! {
    /// The `MaskValid` flags of the tables stream header: one bit per table number.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MaskValid: u64 {
        const MODULE = 1 << 0x00;
        const TYPE_REF = 1 << 0x01;
        const TYPE_DEF = 1 << 0x02;
        const FIELD = 1 << 0x04;
        const METHOD_DEF = 1 << 0x06;
        const PARAM = 1 << 0x08;
        const INTERFACE_IMPL = 1 << 0x09;
        const MEMBER_REF = 1 << 0x0A;
        const CONSTANT = 1 << 0x0B;
        const CUSTOM_ATTRIBUTE = 1 << 0x0C;
        const FIELD_MARSHAL = 1 << 0x0D;
        const DECL_SECURITY = 1 << 0x0E;
        const CLASS_LAYOUT = 1 << 0x0F;
        const FIELD_LAYOUT = 1 << 0x10;
        const STAND_ALONE_SIG = 1 << 0x11;
        const EVENT_MAP = 1 << 0x12;
        const EVENT = 1 << 0x14;
        const PROPERTY_MAP = 1 << 0x15;
        const PROPERTY = 1 << 0x17;
        const METHOD_SEMANTICS = 1 << 0x18;
        const METHOD_IMPL = 1 << 0x19;
        const MODULE_REF = 1 << 0x1A;
        const TYPE_SPEC = 1 << 0x1B;
        const IMPL_MAP = 1 << 0x1C;
        const FIELD_RVA = 1 << 0x1D;
        const ASSEMBLY = 1 << 0x20;
        const ASSEMBLY_PROCESSOR = 1 << 0x21;
        const ASSEMBLY_OS = 1 << 0x22;
        const ASSEMBLY_REF = 1 << 0x23;
        const ASSEMBLY_REF_PROCESSOR = 1 << 0x24;
        const ASSEMBLY_REF_OS = 1 << 0x25;
        const FILE = 1 << 0x26;
        const EXPORTED_TYPE = 1 << 0x27;
        const MANIFEST_RESOURCE = 1 << 0x28;
        const NESTED_CLASS = 1 << 0x29;
        const GENERIC_PARAM = 1 << 0x2A;
        const METHOD_SPEC = 1 << 0x2B;
        const GENERIC_PARAM_CONSTRAINT = 1 << 0x2C;
    }
}

impl From<u64> for MaskValid {
    fn from(bits: u64) -> Self {
        Self::from_bits_retain(bits)
    }
}

impl MaskValid {
    /// The tables whose bit is set, ordered by table number. Bits without a known table yield
    /// [`MetadataTable::Other`].
    pub fn tables(self) -> impl Iterator<Item = MetadataTable> {
        (0..TABLE_COUNT as u8)
            .filter(move |&bit| self.bits() & (1 << bit) != 0)
            .map(MetadataTable::from)
    }
}

/// The layout of a table in the `#~` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TableInfo {
    pub table: MetadataTable,
    pub row_count: u32,
    /// Offset of the table relative to the start of the table data.
    pub offset: u32,
    pub bytes_per_row: u32,
    /// Set if the row count exceeds the file. The row count is then 0.
    pub is_invalid: bool,
}

const ROW_COUNTS_OFFSET: usize = TablesStreamHeader::SIZE;
const EXTRA_DATA_SIZE: usize = 4;

/// The header of the `#~` (tables) stream with the parsed metadata tables.
#[derive(Debug)]
pub struct MetadataTablesHeader<'a> {
    pub offset: FileOffset,
    pub header: &'a TablesStreamHeader,
    data: &'a [u8],
    table_infos: Result<Vec<TableInfo>>,
    tables: Result<Tables>,
}

impl<'a> MetadataTablesHeader<'a> {
    /// Parse the stream header at `offset` in the file `data`. The row counts and the tables
    /// are parsed too; errors there are reported by [`Self::table_infos`] and [`Self::tables`].
    pub fn parse(data: &'a [u8], offset: usize) -> Result<Self> {
        let header = TablesStreamHeader::parse(data, offset)?;
        let offset = file_offset(offset, "tables stream")?;
        let mut parsed = Self {
            offset,
            header,
            data,
            table_infos: Ok(Vec::new()),
            tables: Ok(Tables::default()),
        };
        parsed.table_infos = parsed.parse_table_infos();
        parsed.tables = parsed.parse_tables();
        Ok(parsed)
    }

    /// True if 4 bytes of undocumented extra data follow the row counts (`HeapSizes` bit 0x40).
    pub fn has_extra_data(&self) -> bool {
        self.header.heap_sizes().has_extra_data()
    }

    /// File offset directly after the row counts, where the extra data is if present.
    pub fn extra_data_offset(&self) -> FileOffset {
        let row_counts = self.header.mask_valid().bits().count_ones() * 4;
        FileOffset(
            self.offset
                .get()
                .saturating_add(ROW_COUNTS_OFFSET as u32)
                .saturating_add(row_counts),
        )
    }

    /// The extra data, `Ok(None)` if the header has none.
    pub fn extra_data(&self) -> Result<Option<u32>> {
        if !self.has_extra_data() {
            return Ok(None);
        }
        Bytes(self.data)
            .u32(self.extra_data_offset().usize())
            .map(Some)
    }

    /// One entry per table number (64 entries).
    pub fn table_infos(&self) -> Result<&[TableInfo]> {
        self.table_infos.as_deref().map_err(Clone::clone)
    }

    pub fn tables(&self) -> Result<&Tables> {
        self.tables.as_ref().map_err(Clone::clone)
    }

    fn parse_table_infos(&self) -> Result<Vec<TableInfo>> {
        let (row_counts, invalid) = self.row_counts()?;
        let sizes = self.column_sizes(row_counts);
        let mut offset = 0u32;
        (0..TABLE_COUNT)
            .map(|i| {
                let table = MetadataTable::from(i as u8);
                let bytes_per_row = sizes.row_size(table) as u32;
                let info = TableInfo {
                    table,
                    row_count: row_counts[i],
                    offset,
                    bytes_per_row,
                    is_invalid: invalid[i],
                };
                offset = bytes_per_row
                    .checked_mul(info.row_count)
                    .and_then(|size| offset.checked_add(size))
                    .ok_or(malformed("tables stream", "tables exceed 32 bit"))?;
                Ok(info)
            })
            .collect()
    }

    /// The row count of every table and whether it was invalid. Row counts that exceed the
    /// file are set to 0.
    fn row_counts(&self) -> Result<([u32; TABLE_COUNT], [bool; TABLE_COUNT])> {
        let bytes = Bytes(self.data);
        let start = self.offset.usize() + ROW_COUNTS_OFFSET;
        let max_rows = self.data.len().saturating_sub(start);
        let mut row_counts = [0; TABLE_COUNT];
        let mut invalid = [false; TABLE_COUNT];
        for (n, table) in self.header.mask_valid().tables().enumerate() {
            let i = table.value() as usize;
            let count = bytes.u32(start + n * 4)?;
            if count as usize > max_rows {
                invalid[i] = true;
            } else {
                row_counts[i] = count;
            }
        }
        Ok((row_counts, invalid))
    }

    fn column_sizes(&self, row_counts: [u32; TABLE_COUNT]) -> ColumnSizes {
        ColumnSizes {
            heap_sizes: self.header.heap_sizes(),
            index_sizes: IndexSizes::new(row_counts),
        }
    }

    fn parse_tables(&self) -> Result<Tables> {
        let infos = self.table_infos()?;
        let mut row_counts = [0; TABLE_COUNT];
        for (count, info) in row_counts.iter_mut().zip(infos) {
            *count = info.row_count;
        }
        let extra_data_size = if self.has_extra_data() {
            EXTRA_DATA_SIZE
        } else {
            0
        };
        let start = self.extra_data_offset().usize() + extra_data_size;
        let parser = TableParser {
            data: Bytes(self.data).tail(start)?,
            infos,
            sizes: &self.column_sizes(row_counts),
        };
        Tables::parse(&parser)
    }
}
