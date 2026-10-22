#![cfg_attr(all(feature = "std", feature = "mmap"), doc = include_str!("../README.md"))]
#![cfg_attr(
    not(all(feature = "std", feature = "mmap")),
    doc = "Parser for Windows Portable Executable (PE) files, a port of the C# library PeNet."
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[macro_use]
pub(crate) mod macros;

pub mod address;
#[cfg(feature = "authenticode")]
pub mod authenticode;
pub(crate) mod bytes;
pub mod editor;
mod error;
pub mod imp_hash;
mod lazy;
#[cfg(feature = "mmap")]
mod mmap;
#[cfg(feature = "dotnet")]
pub mod net;
pub mod pe;
mod pe_file;
#[cfg(feature = "resources")]
pub mod resource;

pub use address::{FileOffset, Rva, Va};
pub use error::{Error, Result};
#[cfg(feature = "mmap")]
pub use mmap::MmFile;
pub use pe_file::PeFile;
