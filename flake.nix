{
  description = "Rust implementation of the Zstandard Seekable Format";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    systems.url = "github:nix-systems/default";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      self,
      flake-parts,
      systems,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import systems;
      perSystem =
        {
          config,
          pkgs,
          ...
        }:
        {
          packages = {
            zeekstd = pkgs.callPackage ./build.nix { };
            default = config.packages.zeekstd;
          };

          checks = {
            clippy = config.packages.zeekstd.overrideAttrs (
              _: previousAttrs: {
                pname = previousAttrs.pname + "-clippy";
                nativeCheckInputs = (previousAttrs.nativeCheckInputs or [ ]) ++ [ pkgs.clippy ];
                checkPhase = "cargo clippy";
              }
            );
            rustfmt = config.packages.zeekstd.overrideAttrs (
              _: previousAttrs: {
                pname = previousAttrs.pname + "-rustfmt";
                nativeCheckInputs = (previousAttrs.nativeCheckInputs or [ ]) ++ [ pkgs.rustfmt ];
                checkPhase = "cargo fmt --check";
              }
            );
          };

          devShells = {
            default = pkgs.mkShell {
              packages = [
                pkgs.cargo-edit
                # takes a long time to build rustup
                # pkgs.cargo-msrv
              ];
            };
            fuzz = pkgs.mkShell {
              packages =
                let
                  extended = pkgs.extend inputs.rust-overlay.overlays.default;
                in
                [
                  extended.cargo-fuzz
                  extended.rust-bin.nightly.latest.default
                ];
            };
          };
        };
    };
}
