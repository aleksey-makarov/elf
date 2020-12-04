{ mkDerivation, base, binary, bytestring, directory, exceptions
, filepath, hpack, lens, mtl, prettyprinter, singletons, stdenv
, tasty, tasty-golden, tasty-hunit, template-haskell, typed-process
}:
mkDerivation {
  pname = "elf";
  version = "0.31";
  src = ./.;
  libraryHaskellDepends = [
    base binary bytestring exceptions lens mtl prettyprinter singletons
    template-haskell
  ];
  libraryToolDepends = [ hpack ];
  testHaskellDepends = [
    base binary bytestring directory exceptions filepath prettyprinter
    singletons tasty tasty-golden tasty-hunit typed-process
  ];
  prePatch = "hpack";
  homepage = "https://github.com/aleksey-makarov/elf";
  description = "An Elf parser";
  license = stdenv.lib.licenses.bsd3;
}
