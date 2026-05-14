{
  gnutar,
  lib,
  runCommand,
  rustPlatform,
  versionCheckHook,
}:
let
  cargoToml = builtins.fromTOML (builtins.readFile ./cli/Cargo.toml);
in
rustPlatform.buildRustPackage (finalAttrs: {
  pname = cargoToml.package.name;
  inherit (cargoToml.package) version;

  src = lib.sourceFilesBySuffices ./. [
    ".rs"
    ".toml"
    ".lock"
    ".md"
    ".txt"
  ];

  nativeInstallCheckInputs = [ versionCheckHook ];
  doInstallCheck = true;

  cargoLock.lockFile = ./Cargo.lock;
  cargoBuildFlags = [ "--package zeekstd_cli" ];

  passthru.tarball =
    runCommand "${finalAttrs.finalPackage.name}.tar.gz" { nativeBuildInputs = [ gnutar ]; }
      ''
        tar -czf $out -C "${finalAttrs.finalPackage}/bin" zeekstd
      '';

  meta = {
    homepage = "https://github.com/rorosen/zeekstd";
    license = lib.licenses.bsd2;
    maintainers = with lib.maintainers; [ rorosen ];
    mainProgram = "zeekstd";
  };
})
