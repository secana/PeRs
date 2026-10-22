//! A write once cell for cached parse results: thread safe with `std`, single threaded without.
#![cfg(any(feature = "dotnet", feature = "authenticode"))]

#[cfg(feature = "std")]
pub(crate) type Lazy<T> = std::sync::OnceLock<T>;

#[cfg(not(feature = "std"))]
pub(crate) type Lazy<T> = core::cell::OnceCell<T>;

/// Get the cached result or compute it. Errors are cached too and cloned on every access.
pub(crate) fn cached<T>(
    cell: &Lazy<crate::Result<T>>,
    init: impl FnOnce() -> crate::Result<T>,
) -> crate::Result<&T> {
    cell.get_or_init(init).as_ref().map_err(Clone::clone)
}
