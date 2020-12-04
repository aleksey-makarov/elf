let
  pkgs = import <nixpkgs> { };

in
  { elf = pkgs.haskellPackages.callPackage ./elf.nix { };
  }
