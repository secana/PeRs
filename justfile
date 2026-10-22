default:
    @just --list

build:
    cargo build

test:
    cargo test

clippy:
    cargo clippy --all-targets -- -D warnings

fmt:
    cargo fmt

fmt-check:
    cargo fmt -- --check

# Build every feature on its own and without std.
features:
    cargo build --no-default-features
    cargo build --no-default-features --features resources
    cargo build --no-default-features --features dotnet
    cargo build --no-default-features --features authenticode
    cargo build --no-default-features --features std
    cargo build --no-default-features --features mmap

# Build the docs with and without default features, failing on warnings.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --no-default-features

check: fmt-check clippy test features doc
