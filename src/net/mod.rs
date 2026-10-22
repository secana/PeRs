//! .NET (CLR) metadata: the metadata root, its heaps and the metadata tables.

mod coded_index;
mod heaps;
mod metadata_header;
mod net_guids;
mod tables;
mod tables_header;
mod type_ref_hash;

pub use coded_index::{CodedIndex, MetadataTable};
pub use heaps::{BlobHeap, GuidHeap, StringsHeap, UserString, UserStrings, UserStringsHeap};
pub use metadata_header::{MetadataHeader, StreamHeader};
pub use tables::*;
pub use tables_header::{
    HeapSizes, MaskValid, MetadataTablesHeader, TableInfo, TablesStreamHeader,
};

pub(crate) use net_guids::{com_type_lib_id, module_version_ids};
pub(crate) use type_ref_hash::type_ref_hash;

use crate::address::FileOffset;
use crate::error::{Result, malformed};

const _: () = assert!(TablesStreamHeader::SIZE == 0x18);

fn file_offset(offset: usize, structure: &'static str) -> Result<FileOffset> {
    u32::try_from(offset)
        .map(FileOffset)
        .map_err(|_| malformed(structure, "offset exceeds 32 bit"))
}
