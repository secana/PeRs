//! Memory mapped files.

use core::ops::{Deref, DerefMut};
use std::fs::{File, OpenOptions};
use std::path::Path;

use memmap2::{Mmap, MmapMut};

use crate::error::{Error, Result};

#[derive(Debug)]
enum Map {
    ReadOnly(Mmap),
    ReadWrite(MmapMut),
}

/// A memory mapped file, the fastest way to parse large files:
/// `PeFile::parse(&MmFile::open_read_only(path)?)`.
///
/// The mapping is only valid as long as no other process truncates the file, the usual
/// contract of memory mapped files.
#[derive(Debug)]
pub struct MmFile {
    map: Map,
}

impl MmFile {
    /// Map the file for reading.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)?;
        // SAFETY: See the type documentation.
        let map = unsafe { Mmap::map(&file)? };
        Ok(Self {
            map: Map::ReadOnly(map),
        })
    }

    /// Map the file for reading and writing. Writes through [`MmFile::as_mut_slice`] go directly
    /// to the file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        // SAFETY: See the type documentation.
        let map = unsafe { MmapMut::map_mut(&file)? };
        Ok(Self {
            map: Map::ReadWrite(map),
        })
    }

    /// The mapped bytes for writing. Fails for read only mappings.
    pub fn as_mut_slice(&mut self) -> Result<&mut [u8]> {
        match &mut self.map {
            Map::ReadOnly(_) => Err(Error::InvalidOperation("the file is mapped read only")),
            Map::ReadWrite(map) => Ok(map.deref_mut()),
        }
    }
}

impl Deref for MmFile {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match &self.map {
            Map::ReadOnly(map) => map,
            Map::ReadWrite(map) => map,
        }
    }
}

impl AsRef<[u8]> for MmFile {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
