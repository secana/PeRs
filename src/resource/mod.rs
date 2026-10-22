//! Resources: version information and icons.

mod icon;
mod version_info;

use alloc::vec::Vec;

pub use icon::*;
pub use version_info::*;

/// The version information and icon resources of a PE file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resources<'a> {
    /// The first version information resource.
    pub version_info: Option<VsVersionInfo<'a>>,
    pub icons: Vec<Icon<'a>>,
    pub group_icon_directories: Vec<GroupIconDirectory<'a>>,
}
