/// Define an enum over an integer. PE files may contain any value, so every enum has an
/// `Other(raw)` variant for values without a name. Conversions in both directions are lossless.
///
/// With `other = "..."` after the type, every variant takes a description (`Variant = value =>
/// "description"`) and the enum gets a `description()` method, which returns the `other` text for
/// `Other` values.
macro_rules! pe_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident: $ty:ty, other = $other:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:expr => $description:literal
            ),* $(,)?
        }
    ) => {
        pe_enum! {
            $(#[$meta])*
            $vis enum $name: $ty {
                $(
                    $(#[$variant_meta])*
                    $variant = $value
                ),*
            }
        }

        impl $name {
            /// Human readable description.
            pub const fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $description,)*
                    Self::Other(_) => $other,
                }
            }
        }
    };
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident: $ty:ty {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:expr
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            /// A value without a name.
            Other($ty),
        }

        impl $name {
            /// The raw value.
            pub const fn value(self) -> $ty {
                match self {
                    $(Self::$variant => $value,)*
                    Self::Other(value) => value,
                }
            }

            /// The variant name, `None` for [`Self::Other`].
            pub const fn name(self) -> Option<&'static str> {
                match self {
                    $(Self::$variant => Some(stringify!($variant)),)*
                    Self::Other(_) => None,
                }
            }
        }

        impl From<$ty> for $name {
            fn from(value: $ty) -> Self {
                $(
                    if value == $value {
                        return Self::$variant;
                    }
                )*
                Self::Other(value)
            }
        }

        impl From<$name> for $ty {
            fn from(value: $name) -> Self {
                value.value()
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, "{:#x}", self.value()),
                }
            }
        }
    };
}

/// Define a fixed layout structure that can be referenced directly in the file data. Fields are
/// stored little endian; every field gets a getter returning the native or a typed value.
macro_rules! pe_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field:ident: $raw:ty => $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq,
            zerocopy::FromBytes, zerocopy::IntoBytes, zerocopy::KnownLayout, zerocopy::Immutable, zerocopy::Unaligned,
        )]
        #[repr(C)]
        $vis struct $name {
            $(pub(crate) $field: $raw,)*
        }

        impl $crate::macros::LeValue for $name {
            type Native = $name;

            fn value(&self) -> $name {
                *self
            }
        }

        #[allow(dead_code)]
        impl $name {
            /// Size of the structure in bytes.
            pub const SIZE: usize = size_of::<Self>();

            /// Reference the structure at `offset` in `data`.
            pub fn parse(data: &[u8], offset: usize) -> $crate::Result<&Self> {
                $crate::bytes::Bytes(data).read(offset)
            }

            $(
                $(#[$field_meta])*
                pub fn $field(&self) -> $ty {
                    <$ty>::from($crate::macros::LeValue::value(&self.$field))
                }
            )*
        }
    };
}

/// Forward getters of an enum over a 32 and a 64 bit layout (`Pe32`/`Pe64` variants) to the
/// layout, converting the value with `Into`.
macro_rules! forward {
    ($($name:ident -> $ty:ty),* $(,)?) => {
        $(
            pub fn $name(&self) -> $ty {
                match self {
                    Self::Pe32(h) => h.$name().into(),
                    Self::Pe64(h) => h.$name().into(),
                }
            }
        )*
    };
}

/// Native value of a little endian field.
pub(crate) trait LeValue {
    type Native;

    fn value(&self) -> Self::Native;
}

impl LeValue for u8 {
    type Native = u8;

    fn value(&self) -> u8 {
        *self
    }
}

macro_rules! le_value {
    ($($le:ty => $native:ty),*) => {
        $(
            impl LeValue for $le {
                type Native = $native;

                fn value(&self) -> $native {
                    self.get()
                }
            }
        )*
    };
}

le_value!(
    zerocopy::little_endian::U16 => u16,
    zerocopy::little_endian::U32 => u32,
    zerocopy::little_endian::U64 => u64
);

impl<T: LeValue, const N: usize> LeValue for [T; N] {
    type Native = [T::Native; N];

    fn value(&self) -> Self::Native {
        core::array::from_fn(|i| self[i].value())
    }
}

/// Define the 32 and 64 bit layouts of a structure from one field list and forward the getters
/// of `$target`, an enum over both layouts, to them. Every field is marked:
///
/// - `fixed name: Raw => Type`: the same in both layouts,
/// - `ptr name`: 4 bytes in 32 bit files and 8 bytes in 64 bit files, read as `u64`,
/// - `pe32 name: Raw => Type` and `pe64 name: Raw => Type`: only in one layout. Their getters are
///   not forwarded.
macro_rules! pe_layouts {
    (
        for $target:ty;
        $(#[$meta32:meta])*
        pub struct $name32:ident;
        $(#[$meta64:meta])*
        pub struct $name64:ident;
        fields { $($fields:tt)* }
    ) => {
        pe_layouts!(@munch [$target; $(#[$meta32])* $name32; $(#[$meta64])* $name64] [] [] [] $($fields)*);
    };
    (@munch $head:tt [$($f32:tt)*] [$($f64:tt)*] [$($fwd:tt)*] fixed $name:ident: $raw:ty => $ty:ty, $($rest:tt)*) => {
        pe_layouts!(@munch $head [$($f32)* $name: $raw => $ty,] [$($f64)* $name: $raw => $ty,] [$($fwd)* $name -> $ty,] $($rest)*);
    };
    (@munch $head:tt [$($f32:tt)*] [$($f64:tt)*] [$($fwd:tt)*] ptr $name:ident, $($rest:tt)*) => {
        pe_layouts!(@munch $head
            [$($f32)* $name: zerocopy::little_endian::U32 => u32,]
            [$($f64)* $name: zerocopy::little_endian::U64 => u64,]
            [$($fwd)* $name -> u64,] $($rest)*);
    };
    (@munch $head:tt [$($f32:tt)*] [$($f64:tt)*] [$($fwd:tt)*] pe32 $name:ident: $raw:ty => $ty:ty, $($rest:tt)*) => {
        pe_layouts!(@munch $head [$($f32)* $name: $raw => $ty,] [$($f64)*] [$($fwd)*] $($rest)*);
    };
    (@munch $head:tt [$($f32:tt)*] [$($f64:tt)*] [$($fwd:tt)*] pe64 $name:ident: $raw:ty => $ty:ty, $($rest:tt)*) => {
        pe_layouts!(@munch $head [$($f32)*] [$($f64)* $name: $raw => $ty,] [$($fwd)*] $($rest)*);
    };
    (@munch [$target:ty; $(#[$meta32:meta])* $name32:ident; $(#[$meta64:meta])* $name64:ident]
        [$($f32:tt)*] [$($f64:tt)*] [$($fwd:tt)*]) => {
        pe_struct! {
            $(#[$meta32])*
            pub struct $name32 { $($f32)* }
        }

        pe_struct! {
            $(#[$meta64])*
            pub struct $name64 { $($f64)* }
        }

        impl $target {
            forward!($($fwd)*);
        }
    };
}
