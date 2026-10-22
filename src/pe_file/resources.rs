//! Accessors for version information and icons.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::PeFile;
use crate::error::Result;
use crate::pe::{ResourceEntry, ResourceType};
use crate::resource::{GroupIconDirectory, Icon, Resources, VsVersionInfo};

/// The data of a resource found in the resource tree.
struct ResourceLocation<'a> {
    /// ID of the name level entry, e.g. the icon ID.
    id: u32,
    offset: usize,
    size: usize,
    data: &'a [u8],
}

impl<'a> ResourceLocation<'a> {
    /// The resource data, `None` if it exceeds the file.
    fn bytes(&self) -> Option<&'a [u8]> {
        self.data
            .get(self.offset..self.offset.checked_add(self.size)?)
    }
}

impl<'a> PeFile<'a> {
    /// The version information and icons, `Ok(None)` if the file has none of them.
    pub fn resources(&self) -> Result<Option<Resources<'a>>> {
        let versions = self.locate_resources(ResourceType::Version)?;
        let icons = self.locate_resources(ResourceType::Icon)?;
        let groups = self.locate_resources(ResourceType::GroupIcon)?;
        if versions.is_empty() && icons.is_empty() && groups.is_empty() {
            return Ok(None);
        }
        Ok(Some(Resources {
            version_info: versions
                .first()
                .and_then(|location| VsVersionInfo::parse(self.data, location.offset).ok()),
            icons: icons
                .iter()
                .filter_map(|location| {
                    location.bytes().map(|data| Icon {
                        id: location.id,
                        data,
                    })
                })
                .collect(),
            group_icon_directories: groups
                .iter()
                .filter_map(|location| {
                    GroupIconDirectory::parse(self.data, location.offset, location.size).ok()
                })
                .collect(),
        }))
    }

    /// All icons as `.ico` files, independent of group icon directories.
    pub fn icons(&self) -> Result<impl Iterator<Item = Cow<'a, [u8]>> + use<'a>> {
        let icons = self.resources()?.map(|r| r.icons).unwrap_or_default();
        Ok(icons.into_iter().filter_map(|icon| icon.to_ico()))
    }

    /// The icons of every group icon directory as `.ico` files. Entries referencing missing or
    /// invalid icons are skipped.
    pub fn group_icons(&self) -> Result<Vec<Vec<Cow<'a, [u8]>>>> {
        let Some(resources) = self.resources()? else {
            return Ok(Vec::new());
        };
        Ok(resources
            .group_icon_directories
            .iter()
            .map(|directory| {
                directory
                    .entries
                    .iter()
                    .flat_map(|entry| entry.associated_icons(&resources.icons))
                    .filter_map(Icon::to_ico)
                    .collect()
            })
            .collect())
    }

    /// All resources of a type: type level, name/ID level and language level with the data.
    fn locate_resources(&self, resource_type: ResourceType) -> Result<Vec<ResourceLocation<'a>>> {
        let Some(root) = self.resource_directory()? else {
            return Ok(Vec::new());
        };
        let sections = self.section_headers()?;
        let mut locations = Vec::new();
        let type_entries = root
            .entries
            .iter()
            .filter(|e| e.raw.id() == resource_type.value());
        for name_entry in children(type_entries)? {
            let language_entries = name_entry.directory()?.entries;
            locations.extend(language_entries.iter().filter_map(|language_entry| {
                let data_entry = language_entry.data_entry().ok()?;
                let offset = sections.rva_to_offset(data_entry.offset_to_data()).ok()?;
                Some(ResourceLocation {
                    id: name_entry.raw.id(),
                    offset: offset.usize(),
                    size: data_entry.size() as usize,
                    data: self.data,
                })
            }));
        }
        Ok(locations)
    }
}

/// The entries of the sub directories of `entries`.
fn children<'e, 'a: 'e>(
    entries: impl Iterator<Item = &'e ResourceEntry<'a>>,
) -> Result<Vec<ResourceEntry<'a>>> {
    let mut children = Vec::new();
    for entry in entries {
        children.extend(entry.directory()?.entries);
    }
    Ok(children)
}
