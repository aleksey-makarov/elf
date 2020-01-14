{-# LANGUAGE ScopedTypeVariables #-}

module Data.ElfSpec (spec) where

import Test.Hspec

import Control.Exception (evaluate)
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Char8 as C
import Data.Foldable (find)
import qualified Data.Map as Map
import Data.Maybe
import Data.Binary

import Data.Elf

parseSymbolTables :: Elf -> [[ElfSymbolTableEntry]]
parseSymbolTables e = filter (not . null) $ fmap elfParseSymbolTable $ elfSections e

spec :: Spec
spec = do
    tinyElf    <- runIO $ decodeFile "./testdata/tiny"
    bloatedElf <- runIO $ decodeFile "./testdata/bloated"
    dynsymElf  <- runIO $ decodeFile "./testdata/vdso"

    describe "parseElf" $ do
        it "does not accept an empty elf" $
            evaluate (decode L.empty :: Elf) `shouldThrow` anyErrorCall

        context "Headers parsing" $ do

            it "parses the version" $
                elfVersion tinyElf `shouldBe` 1

            it "parses the architecture" $ do
                elfClass tinyElf    `shouldBe` ELFCLASS64
                elfClass bloatedElf `shouldBe` ELFCLASS32

            it "parses the endianness" $ do
                elfData tinyElf `shouldBe` ELFDATA2LSB

            it "parses the OS ABI" $
                elfOSABI tinyElf `shouldBe` ELFOSABI_SYSV

            it "parses the type" $
                elfType bloatedElf `shouldBe` ET_EXEC

            it "parses the machine type" $ do
                elfMachine tinyElf    `shouldBe` EM_X86_64
                elfMachine bloatedElf `shouldBe` EM_386

            it "parses the entry point" $ do
                elfEntry tinyElf    `shouldBe` 0x4000e0
                elfEntry bloatedElf `shouldBe` 0x8048610

        context "Segment parsing" $ do
            let tinySegments    = elfSegments tinyElf
                bloatedSegments = elfSegments bloatedElf

            it "parses the right amount of segments" $ do
                length tinySegments    `shouldBe` 2
                length bloatedSegments `shouldBe` 9

            it "parses segment types" $
                let segmentTypes = map elfSegmentType tinySegments in
                segmentTypes `shouldBe` [PT_LOAD, PT_NOTE]

            it "parses segment flags" $ do
                let segmentFlags = map (splitBits . elfSegmentFlags) tinySegments
                segmentFlags !! 0 `shouldMatchList` [PF_R, PF_X]
                segmentFlags !! 1 `shouldMatchList` [PF_R]

        context "Section parsing" $ do
            let tinySections    = elfSections tinyElf
                bloatedSections = elfSections bloatedElf

            it "parses the right amount of sections" $ do
                length tinySections    `shouldBe` 3
                length bloatedSections `shouldBe` 31

            it "parses the section in the right order" $ do
                map (nameToString . elfSectionName) tinySections `shouldBe` [ "", ".text", ".shstrtab" ]

            it "parses the section types" $
                let sectionTypes = map elfSectionType bloatedSections in
                take 5 sectionTypes `shouldBe` [ SHT_NULL, SHT_PROGBITS, SHT_NOTE
                                               , SHT_NOTE, SHT_EXT 1879048182]

            it "parses the data" $
                let comment  = find (\sec -> (nameToString $ elfSectionName sec) == ".comment") bloatedSections
                    expected = C.pack . concat $ [ "GCC: (GNU) 6.3.1 20161221 (Red Hat 6.3.1-1)\NUL"
                                                 , "clang version 3.8.1 (tags/RELEASE_381/final)\NUL"
                                                 ]
                in
                fmap elfSectionData comment `shouldBe` Just expected

    describe "findSymbolDefinition" $ do
        let tinySymbols    = parseSymbolTables tinyElf
            bloatedSymbols = parseSymbolTables bloatedElf

        it "parses stripped symbol" $
            -- This binary was stripped
            concat tinySymbols `shouldSatisfy` all (isNothing . steName)

        let namedBloatedSymbols =
                let go sym = fmap (\ name -> (name, sym)) $ steName sym
                in Map.fromList $ catMaybes $ map go $ concat bloatedSymbols

            member k = Map.member (C.pack k)
            (!?) m k = m Map.!? (C.pack k)

        it "parses symbol symbol names" $ do
            namedBloatedSymbols `shouldSatisfy` member "_init"
            namedBloatedSymbols `shouldSatisfy` member "main"

        let initSymbol  = namedBloatedSymbols !? "_init"
            fnameSymbol = namedBloatedSymbols !? "bloated.cpp"

        it "parses symbol address" $
            fmap steValue initSymbol `shouldBe` Just 0x0804850c

        it "parses symbol type" $ do
            fmap steType initSymbol  `shouldBe` Just STT_Func
            fmap steType fnameSymbol `shouldBe` Just STT_File
    describe "parse DynSym symbols" $ do
        let dynSymbols    = parseSymbolTables dynsymElf
        it "parses dyn symbol table" $ do
          dynSymbols `shouldNotSatisfy` null
        it "parse (x86_64) vdso dyn symbols" $ do
          let dynSyms = concat dynSymbols
          filter (\e -> (nameToString $ steName e) == "__vdso_time")          dynSyms `shouldNotSatisfy` null
          filter (\e -> (nameToString $ steName e) == "__vdso_getcpu")        dynSyms `shouldNotSatisfy` null
          filter (\e -> (nameToString $ steName e) == "__vdso_clock_gettime") dynSyms `shouldNotSatisfy` null
          filter (\e -> (nameToString $ steName e) == "__vdso_gettimeofday")  dynSyms `shouldNotSatisfy` null
