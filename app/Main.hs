{-# LANGUAGE OverloadedStrings #-}

import Data.ByteString as B
import Data.Elf
import Data.Text.Prettyprint.Doc
import Data.Text.Prettyprint.Doc.Util
import System.Environment

formatElf :: Elf -> Doc ()
formatElf elf =
    vsep [ "elfClass:" <+> (viaShow $ elfClass elf) -- ElfClass     Identifies the class of the object file.
         , "elfData:"  <+> (viaShow $ elfData elf) -- ElfData      Identifies the data encoding of the object file.
         , "elfVersion:" <+> (viaShow $ elfVersion elf) -- Int          Identifies the version of the object file format.
         , "elfOSABI:" <+> (viaShow $ elfOSABI elf) -- ElfOSABI     Identifies the operating system and ABI for which the object is prepared.
         , "elfABIVersion:" <+> (viaShow $ elfABIVersion elf) -- Int          Identifies the ABI version for which the object is prepared.
         , "elfType:" <+> (viaShow $ elfType elf) -- ElfType      Identifies the object file type.
         , "elfMachine:" <+> (viaShow $ elfMachine elf) -- ElfMachine   Identifies the target architecture.
         , "elfEntry:" <+> (viaShow $ elfEntry elf) -- Word64       Virtual address of the program entry point. 0 for non-executable Elfs.
--         , elfSections   elf -- [ElfSection] List of sections in the file.
--         , elfSegments   elf -- [ElfSegment] List of segments in the file.
         ]

printElf :: String -> IO ()
printElf fileName = do
    bs <- B.readFile fileName
    putDocW 80 $ (formatElf $ parseElf bs) <> line

main :: IO ()
main = do
    args <- getArgs
    mapM_ printElf args
