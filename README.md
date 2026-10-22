# PeRs

PeRs is a parser for Windows Portable Executable (PE) files. It started as a port of the C#
library [PeNet](https://github.com/secana/PeNet) and is tested against PeNet's test cases and test
binaries. PeRs borrows the file data instead of copying it: fixed layout headers and tables are
referenced in place, variable structures such as imports, version information, .NET tables and
certificates are decoded into small owned values. The API uses typed addresses, real enums and
`Result<Option<T>>` accessors that tell absent and malformed structures apart. It needs no native
Windows APIs and works in `no_std` environments with `alloc`.

## Features

- All native PE headers: DOS, NT, file and optional header (32 and 64 bit), sections, data
  directories
- Imports, delay imports, exports (including forwarded exports), bound imports, relocations,
  exception directory with unwind information, debug directory (CodeView PDB info), TLS callbacks,
  load config, COM descriptor
- Resources: version information and icons as `.ico` files
- .NET metadata: metadata header, heaps and all metadata tables
- Hashes: MD5, SHA-1, SHA-256, ImpHash, TypeRefHash, Authenticode hash
- Authenticode: signing certificate, signature validation, signing time stamp, CRL URLs
- Editing with `PeEditor`: add and remove sections, add imports

## Usage

```rust,no_run
use pers::PeFile;

let data = std::fs::read("firefox.exe")?;
let pe = PeFile::parse(&data)?;

let file_header = pe.nt_headers().file_header;
println!("Machine: {}", file_header.machine().description());
println!("SHA-256: {}", hex::encode(pe.sha256()));

for section in pe.section_headers()? {
    println!("{} {}", section.name(), section.virtual_address());
}

// Ok(None) if the file has no imports, Err if they are malformed.
if let Some(imports) = pe.imported_functions()? {
    for import in imports {
        println!("{} {:?}", import.dll, import.name);
    }
}

println!("Signed: {}", pe.is_signed());
println!("Valid signature: {}", pe.has_valid_signature());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Large files can be memory mapped:

```rust,no_run
use pers::{MmFile, PeFile};

let file = MmFile::open_read_only("large.dll")?;
let pe = PeFile::parse(&file)?;
# Ok::<(), pers::Error>(())
```

Edits go through `PeEditor`, which owns the data:

```rust,no_run
use pers::editor::PeEditor;

let mut editor = PeEditor::new(std::fs::read("app.exe")?)?;
editor.add_import("gdi32.dll", "StartPage")?;
std::fs::write("app_patched.exe", editor.into_bytes())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Cargo Features

| Feature        | Default | Content                                              |
|----------------|---------|------------------------------------------------------|
| `std`          | yes     | `std::error::Error`, I/O helpers, thread safe caches |
| `mmap`         | yes     | `MmFile` for memory mapped files                     |
| `resources`    | yes     | Version information and icons                        |
| `dotnet`       | yes     | .NET metadata                                        |
| `authenticode` | yes     | Authenticode signatures                              |

Without `std` the crate is `no_std` and needs `alloc`.

## Comparison

| Crate | Formats | Focus | Compared to PeRs |
|---|---|---|---|
| [object](https://crates.io/crates/object) | ELF, Mach-O, PE/COFF, Wasm | Unified zero-copy reading and writing | Multi-format and very mature; no .NET metadata or Authenticode validation |
| [goblin](https://crates.io/crates/goblin) | ELF, Mach-O, PE | Cross-platform parser and loader | Multi-format; covers the PE basics, no .NET metadata or signature validation |
| [pelite](https://crates.io/crates/pelite) | PE | Low allocation PE reader with resources | Similar borrowing design; no .NET metadata or signature validation |
| [editpe](https://crates.io/crates/editpe) | PE | Editing resources such as icons and version info | Stronger resource editing; less analysis |
| [authenticode](https://crates.io/crates/authenticode) | PE | Authenticode signatures, built on `object` | Signature parsing and hashing; PeRs also verifies signer and counter signer signatures |
| [lief](https://crates.io/crates/lief) | ELF, Mach-O, PE | Bindings to the C++ library LIEF | Very complete, but needs the native library |

PeRs only reads PE files. It combines the native structures with .NET metadata, ImpHash,
TypeRefHash, version information, icons and Authenticode validation in one `no_std` crate, and is
tested against the cases and binaries of PeNet. For tools that need ELF or Mach-O as well, use
`object` or `goblin`.

## Development

```bash
nix develop
just test
just clippy
just fmt
just features   # build every feature combination
```

The tests are ported from PeNet and use its test binaries in `tests/Binaries`. A fuzz target
lives in `fuzz/` (`cargo +nightly fuzz run parse`).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
