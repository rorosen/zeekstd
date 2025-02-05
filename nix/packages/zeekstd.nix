{
  lib,
  rustPlatform,
}:

let
  cargoToml = builtins.fromTOML (builtins.readFile ../../Cargo.toml);
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  inherit (cargoToml.package) version;

  src = lib.sourceFilesBySuffices ../.. [
    ".rs"
    ".toml"
    ".lock"
  ];

  cargoLock = {
    lockFile = ../../Cargo.lock;
    outputHashes."zstd-safe-7.2.1" = "sha256-EsKThcWLUbcjvbABVV7NpRccdj/VGMFiWyrdqI8frOw=";
  };

  stripAllList = [ "bin" ];

  meta = with lib; {
    homepage = "https://github.com/rorosen/zeekstd";
    license = licenses.bsd2;
    maintainers = with lib.maintainers; [ rorosen ];
    mainProgram = "zeekstd";
  };
}
