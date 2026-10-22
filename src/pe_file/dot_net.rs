//! Accessors for the .NET (CLR) metadata.

use alloc::vec::Vec;

use uuid::Uuid;

use super::PeFile;
use crate::error::Result;
use crate::lazy::{Lazy, cached};
use crate::net::{
    BlobHeap, GuidHeap, MetadataHeader, MetadataTablesHeader, StringsHeap, UserStringsHeap,
    com_type_lib_id, module_version_ids, type_ref_hash,
};

/// Cached .NET structures of a [`PeFile`].
#[derive(Debug, Default)]
pub(super) struct DotNetCache<'a> {
    metadata_header: Lazy<Result<Option<MetadataHeader<'a>>>>,
    tables_header: Lazy<Result<Option<MetadataTablesHeader<'a>>>>,
    type_ref_hash: Lazy<Result<Option<[u8; 32]>>>,
    module_version_ids: Lazy<Result<Option<Vec<Uuid>>>>,
    com_type_lib_id: Lazy<Result<Option<Uuid>>>,
}

impl<'a> PeFile<'a> {
    /// True if the file has a CLI (COM descriptor) header.
    pub fn is_dot_net(&self) -> bool {
        matches!(self.com_descriptor(), Ok(Some(_)))
    }

    /// The metadata root referenced by the CLI header.
    pub fn metadata_header(&self) -> Result<Option<&MetadataHeader<'a>>> {
        cached(&self.cache.dot_net.metadata_header, || {
            let Some(com_descriptor) = self.com_descriptor()? else {
                return Ok(None);
            };
            let rva = com_descriptor.meta_data().virtual_address();
            if rva.get() == 0 {
                return Ok(None);
            }
            let offset = self.section_headers()?.rva_to_offset(rva)?;
            MetadataHeader::parse(self.data, offset.usize()).map(Some)
        })
        .map(Option::as_ref)
    }

    /// The `#Strings` heap.
    pub fn metadata_strings(&self) -> Result<Option<StringsHeap<'a>>> {
        self.parse_stream("#Strings", StringsHeap::parse)
    }

    /// The `#US` (user strings) heap.
    pub fn metadata_user_strings(&self) -> Result<Option<UserStringsHeap<'a>>> {
        self.parse_stream("#US", UserStringsHeap::parse)
    }

    /// The `#GUID` heap.
    pub fn metadata_guids(&self) -> Result<Option<GuidHeap<'a>>> {
        self.parse_stream("#GUID", GuidHeap::parse)
    }

    /// The `#Blob` heap.
    pub fn metadata_blob(&self) -> Result<Option<BlobHeap<'a>>> {
        self.parse_stream("#Blob", BlobHeap::parse)
    }

    /// The header of the `#~` stream with all metadata tables.
    pub fn metadata_tables_header(&self) -> Result<Option<&MetadataTablesHeader<'a>>> {
        cached(&self.cache.dot_net.tables_header, || {
            self.parse_stream("#~", |data, offset, _| {
                MetadataTablesHeader::parse(data, offset)
            })
        })
        .map(Option::as_ref)
    }

    /// The TypeRefHash, `Ok(None)` for files without metadata tables or `#Strings` heap.
    pub fn type_ref_hash(&self) -> Result<Option<[u8; 32]>> {
        cached(&self.cache.dot_net.type_ref_hash, || {
            let (Some(tables_header), Some(strings)) =
                (self.metadata_tables_header()?, self.metadata_strings()?)
            else {
                return Ok(None);
            };
            type_ref_hash(tables_header, &strings).map(Some)
        })
        .copied()
    }

    /// The module version ID of each module, `Ok(None)` for files without metadata tables.
    pub fn clr_module_version_ids(&self) -> Result<Option<&[Uuid]>> {
        cached(&self.cache.dot_net.module_version_ids, || {
            let Some(tables_header) = self.metadata_tables_header()? else {
                return Ok(None);
            };
            Ok(Some(module_version_ids(
                tables_header.tables()?,
                self.metadata_guids()?.as_ref(),
            )))
        })
        .map(Option::as_deref)
    }

    /// The COM TypeLib ID of the assembly, `Ok(None)` if it is not specified.
    pub fn clr_com_type_lib_id(&self) -> Result<Option<Uuid>> {
        cached(&self.cache.dot_net.com_type_lib_id, || {
            let (Some(tables_header), Some(strings), Some(blob)) = (
                self.metadata_tables_header()?,
                self.metadata_strings()?,
                self.metadata_blob()?,
            ) else {
                return Ok(None);
            };
            com_type_lib_id(tables_header.tables()?, &strings, &blob)
        })
        .copied()
    }

    /// Parse the first stream with the given name. The stream offset is relative to the
    /// metadata root.
    fn parse_stream<T>(
        &self,
        name: &str,
        parse: impl FnOnce(&'a [u8], usize, usize) -> Result<T>,
    ) -> Result<Option<T>> {
        let Some(header) = self.metadata_header()? else {
            return Ok(None);
        };
        let Some(stream) = header.stream(name) else {
            return Ok(None);
        };
        let offset = header.offset.usize() + stream.stream_offset as usize;
        parse(self.data, offset, stream.size as usize).map(Some)
    }
}
