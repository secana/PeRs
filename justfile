############################################
# Just commands
#
# It's recommended to use the just commands
# instead of the cargo commands, as they
# provide additional functionality.
############################################


##########################################
# Common commands
##########################################

@_default:
    {{just_executable()}} --list

check:
	cargo check

build:
	cargo build

build-release:
	cargo build --release

test:
	cargo nextest run --workspace

test-docs:
  cargo doc --no-deps --document-private-items
  cargo test --doc

clean:
	cargo clean

# Reformat all code `cargo fmt`. If nightly is available, use it for better results
fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    if (rustup toolchain list | grep nightly && rustup component list --toolchain nightly | grep rustfmt) &> /dev/null; then
        echo 'Reformatting Rust code using nightly Rust fmt to sort imports'
		rustup run nightly cargo fmt --all -- --config imports_granularity=Module,group_imports=StdExternalCrate
    else
        echo 'Reformatting Rust with the stable cargo fmt.  Install nightly with `rustup install nightly` for better results'
        cargo fmt --all
    fi

##########################################
# CI commands
##########################################

ci-clippy:
  cargo clippy --workspace --all-targets --all-features -- -D warnings

ci-fmt-check:
  cargo fmt --all -- --check

##########################################
# Aliases
##########################################

alias b := build
alias br := build-release
alias r := run
alias t := test
alias td := test-docs
alias c := check
