{ pkgs }:
{
  zeekstd = pkgs.callPackage ./zeekstd.nix { };
  static = pkgs.pkgsStatic.callPackage ./zeekstd.nix { };
  cross = pkgs.pkgsCross.aarch64-multiplatform.callPackage ./zeekstd.nix { };
}
