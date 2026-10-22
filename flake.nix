{
  description = "Development and build environment for Rust crates";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    crane.url = "github:ipetkov/crane";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , crane
    , rust-overlay
    , ...
    }:
    flake-utils.lib.eachSystem
      [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ]
      (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default;

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;

          buildInputs = [
            pkgs.openssl
          ];

          nativeBuildInputs = [
            pkgs.pkg-config
          ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        crate = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });
      in
      {
        packages.default = crate;

        checks = {
          # Build
          build = crate;

          # Tests
          test = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
          });

          # Docs (fails on warnings for consistency with CI)
          doc = craneLib.cargoDoc (commonArgs // {
            inherit cargoArtifacts;
            RUSTDOCFLAGS = "-D warnings";
          });

          # Lints
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--workspace --all-targets --all-features -- -D warnings";
          });

          fmt = craneLib.cargoFmt {
            inherit src;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.just
            pkgs.cargo-nextest
            pkgs.openssl.dev
            pkgs.pkg-config
          ];

          shellHook = ''
            echo "Rust development environment loaded!"
            echo "Using Rust toolchain: ${rustToolchain.pname or "rust"}-${rustToolchain.version or "latest"}"
            echo "Available tools: cargo, just, cargo-nextest"
          '';
        };
      });
}

