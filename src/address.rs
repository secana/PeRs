//! Typed addresses. Mixing a relative virtual address with a file offset is a type error.

use core::fmt;

macro_rules! address {
    ($(#[$meta:meta])* $name:ident($ty:ty)) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
        pub struct $name(pub $ty);

        impl $name {
            pub const fn get(self) -> $ty {
                self.0
            }
        }

        impl From<$ty> for $name {
            fn from(value: $ty) -> Self {
                Self(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }
    };
}

address!(
    /// A relative virtual address: an address relative to the image base.
    Rva(u32)
);

address!(
    /// A virtual address: image base plus RVA.
    Va(u64)
);

address!(
    /// An offset into the file data.
    FileOffset(u32)
);

impl FileOffset {
    pub(crate) const fn usize(self) -> usize {
        self.0 as usize
    }
}
