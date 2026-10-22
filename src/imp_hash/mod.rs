//! Import hash (ImpHash) as defined by Mandiant: the MD5 of the normalized import list.

mod ordinal_symbol_mapping;

use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use md5::{Digest, Md5};

use crate::bytes::encode_ascii;
use crate::pe::ImportFunction;
use ordinal_symbol_mapping::{Module, lookup};

/// The ImpHash of a list of imported functions, `None` if there are no imports.
pub fn imp_hash(imported_functions: &[ImportFunction]) -> Option<[u8; 16]> {
    if imported_functions.is_empty() {
        return None;
    }
    let imports = imported_functions
        .iter()
        .map(|f| format!("{}{}", library_name(&f.dll), function_name(f)))
        .collect::<Vec<_>>()
        .join(",");
    Some(Md5::digest(encode_ascii(&imports)).into())
}

/// Lowercase library name without the extensions `ocx`, `sys` and `dll`, followed by a dot.
fn library_name(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut parts: Vec<&str> = lower.split('.').collect();
    if parts.len() > 1
        && parts
            .last()
            .is_some_and(|ext| ["ocx", "sys", "dll"].contains(ext))
    {
        parts.pop();
    }
    parts.iter().map(|p| format!("{p}.")).collect()
}

fn function_name(function: &ImportFunction) -> String {
    let name: Cow<str> = match &function.name {
        Some(name) => Cow::Borrowed(name),
        None => match function.dll.to_lowercase().as_str() {
            "oleaut32.dll" => lookup(Module::Oleaut32, function.hint as u32),
            "ws2_32.dll" => lookup(Module::Ws2_32, function.hint as u32),
            "wsock32.dll" => lookup(Module::Wsock32, function.hint as u32),
            _ => Cow::Owned(format!("ord{}", function.hint)),
        },
    };
    name.to_lowercase()
}
