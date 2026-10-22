//! GUIDs which correlate related CLR PE files, see
//! <https://www.virusbulletin.com/virusbulletin/2015/06/using-net-guids-help-hunt-malware/>.

use alloc::vec::Vec;

use uuid::Uuid;

use super::coded_index::{CodedIndex, MetadataTable};
use super::heaps::{BlobHeap, GuidHeap, StringsHeap};
use super::tables::{Tables, TypeRef};
use crate::error::{Result, malformed};

const GUID_STRING_LENGTH: usize = 36;
/// Prolog of a custom attribute value blob.
const CUSTOM_ATTRIBUTE_PROLOG: [u8; 2] = [0x01, 0x00];

/// The module version ID of each module, a new GUID for every build. Nil GUIDs and indices
/// that are not in the `#GUID` heap are skipped.
pub(crate) fn module_version_ids(tables: &Tables, guids: Option<&GuidHeap<'_>>) -> Vec<Uuid> {
    tables
        .module
        .iter()
        .filter_map(|m| guids?.get(m.mvid))
        .filter(|g| !g.is_nil())
        .collect()
}

/// The COM TypeLib ID from the `GuidAttribute` of the assembly, generated at project creation.
/// Follows TypeRef `System.Runtime.InteropServices.GuidAttribute` to its MemberRef, to the
/// CustomAttribute using it and to the GUID string in its value blob.
pub(crate) fn com_type_lib_id(
    tables: &Tables,
    strings: &StringsHeap<'_>,
    blob: &BlobHeap<'_>,
) -> Result<Option<Uuid>> {
    let Some(type_ref) = guid_attribute_row(&tables.type_ref, strings)? else {
        return Ok(None);
    };
    let Some(member_ref) = member_ref_row(tables, type_ref) else {
        return Ok(None);
    };
    for attribute in &tables.custom_attribute {
        if CodedIndex::CustomAttributeType.decode(attribute.r#type)
            != Some((MetadataTable::MemberRef, member_ref))
        {
            continue;
        }
        if let Some(guid) = guid_in_blob(blob.get(attribute.value)?)? {
            return Ok(Some(guid));
        }
    }
    Ok(None)
}

/// The 1 based row of the `GuidAttribute` TypeRef.
fn guid_attribute_row(type_refs: &[TypeRef], strings: &StringsHeap<'_>) -> Result<Option<u32>> {
    for (row, type_ref) in (1..).zip(type_refs) {
        if strings.get(type_ref.type_name)? == "GuidAttribute"
            && strings.get(type_ref.type_namespace)? == "System.Runtime.InteropServices"
        {
            return Ok(Some(row));
        }
    }
    Ok(None)
}

/// The 1 based row of the first MemberRef whose parent is the given TypeRef row.
fn member_ref_row(tables: &Tables, type_ref: u32) -> Option<u32> {
    (1..).zip(&tables.member_ref).find_map(|(row, m)| {
        (CodedIndex::MemberRefParent.decode(m.class) == Some((MetadataTable::TypeRef, type_ref)))
            .then_some(row)
    })
}

/// The GUID string argument of a custom attribute value: prolog, length byte, 36 characters.
fn guid_in_blob(value: &[u8]) -> Result<Option<Uuid>> {
    let Some((prolog, rest)) = value.split_first_chunk::<2>() else {
        return Ok(None);
    };
    let Some((&length, rest)) = rest.split_first() else {
        return Ok(None);
    };
    if *prolog != CUSTOM_ATTRIBUTE_PROLOG || length as usize != GUID_STRING_LENGTH {
        return Ok(None);
    }
    let text = rest
        .get(..GUID_STRING_LENGTH)
        .ok_or(malformed("GuidAttribute", "GUID string exceeds the blob"))?;
    Uuid::try_parse_ascii(text)
        .map(Some)
        .map_err(|_| malformed("GuidAttribute", "invalid GUID string"))
}
