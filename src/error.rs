use crate::address::{FileOffset, Rva};

/// Errors of parsing and editing PE files. The variants carry no heap data, so errors are cheap
/// to clone and work without `std`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("{length} bytes at offset {offset:#x} exceed the data of {data_length} bytes")]
    OutOfBounds {
        offset: u64,
        length: u64,
        data_length: u64,
    },

    #[error("string at offset {offset:#x} is not terminated")]
    UnterminatedString { offset: u64 },

    #[error("not a PE file: {0}")]
    NotAPeFile(&'static str),

    #[error("RVA {0} is not mapped to a section")]
    RvaNotMapped(Rva),

    #[error("file offset {0} is not part of a section")]
    OffsetNotMapped(FileOffset),

    #[error("malformed {structure}: {reason}")]
    Malformed {
        structure: &'static str,
        reason: &'static str,
    },

    #[error("unsupported: {0}")]
    Unsupported(&'static str),

    #[error("invalid operation: {0}")]
    InvalidOperation(&'static str),

    #[cfg(feature = "std")]
    #[error("I/O error: {0}")]
    Io(std::io::ErrorKind),
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub(crate) fn malformed(structure: &'static str, reason: &'static str) -> Error {
    Error::Malformed { structure, reason }
}
