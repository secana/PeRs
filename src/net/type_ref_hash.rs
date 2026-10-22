use alloc::borrow::Cow;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use super::coded_index::MetadataTable;
use super::heaps::StringsHeap;
use super::tables_header::MetadataTablesHeader;
use crate::error::{Result, malformed};

/// The TypeRefHash of a .NET assembly: the SHA-256 of all `namespace-name` pairs of the
/// TypeRef table, sorted like PeNet and joined with commas.
pub(crate) fn type_ref_hash(
    tables_header: &MetadataTablesHeader<'_>,
    strings: &StringsHeap<'_>,
) -> Result<[u8; 32]> {
    let infos = tables_header.table_infos()?;
    if infos
        .get(MetadataTable::TypeRef.value() as usize)
        .is_some_and(|info| info.is_invalid)
    {
        return Err(malformed("TypeRef table", "row count exceeds the file"));
    }
    let mut pairs = tables_header
        .tables()?
        .type_ref
        .iter()
        .map(|t| Ok((strings.get(t.type_namespace)?, strings.get(t.type_name)?)))
        .collect::<Result<Vec<(Cow<'_, str>, Cow<'_, str>)>>>()?;
    pairs.sort_by_cached_key(|(namespace, name)| (culture_key(namespace), culture_key(name)));
    let mut hasher = Sha256::new();
    for (i, (namespace, name)) in pairs.iter().enumerate() {
        if i > 0 {
            hasher.update(b",");
        }
        hasher.update(namespace.as_bytes());
        hasher.update(b"-");
        hasher.update(name.as_bytes());
    }
    Ok(hasher.finalize().into())
}

/// Sort key which approximates the culture sensitive string comparison PeNet sorts with
/// (`OrderBy` with the default comparer) for the ASCII strings of the `#Strings` heap:
/// punctuation before digits before letters, letters compared case insensitive first and
/// lowercase before uppercase on ties.
fn culture_key(s: &str) -> (Vec<(u8, char)>, Vec<bool>) {
    let primary = s
        .chars()
        .map(|c| match c {
            c if c.is_ascii_digit() => (1, c),
            c if c.is_ascii_alphabetic() => (2, c.to_ascii_lowercase()),
            c => (0, c),
        })
        .collect();
    let tertiary = s.chars().map(|c| c.is_ascii_uppercase()).collect();
    (primary, tertiary)
}
