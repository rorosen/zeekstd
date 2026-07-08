{
  description = "Rust implementation of the Zstandard Seekable Format";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:NixOS/flake-compat";
      flake = false;
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      perSystem =
        {
          config,
          pkgs,
          ...
        }:
        {
          packages = {
            default = config.packages.zeekstd;
            zeekstd = pkgs.callPackage ./build.nix { };
            zeekstd-static = pkgs.pkgsStatic.callPackage ./build.nix { };
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
