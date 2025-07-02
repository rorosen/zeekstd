{
  lib,
  rustPlatform,
}:

let
  cargoToml = builtins.fromTOML (builtins.readFile ./cli/Cargo.toml);
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  inherit (cargoToml.package) version;

  src = lib.sourceFilesBySuffices ./. [
    ".rs"
    ".toml"
    ".lock"
    ".md"
    ".txt"
  ];

  cargoLock.lockFile = ./Cargo.lock;
  meta = with lib; {
    homepage = "https://github.com/rorosen/zeekstd";
    license = licenses.bsd2;
    maintainers = with lib.maintainers; [ rorosen ];
    mainProgram = "zeekstd";
  };
}
