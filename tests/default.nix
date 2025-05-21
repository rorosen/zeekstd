{ pkgs }:
{
  cycle = pkgs.callPackage ./cycle.nix { };
  list = pkgs.callPackage ./list.nix { };
  partial = pkgs.callPackage ./partial.nix { };
  output = pkgs.callPackage ./output.nix { };
}
