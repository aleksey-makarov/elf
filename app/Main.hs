{-# LANGUAGE OverloadedStrings #-}

import Data.ByteString as B
import Data.Elf
import Data.Text.Prettyprint.Doc
import Data.Text.Prettyprint.Doc.Util
import System.Environment

formatSection :: ElfSection -> Doc ()
formatSection s =
    let sEntries = [ ("elfSectionName:",      viaShow $elfSectionName s)
                   , ("elfSectionType:",      viaShow $elfSectionType s)
                   , ("elfSectionFlags:",     viaShow $elfSectionFlags s)
                   , ("elfSectionAddr:",      viaShow $elfSectionAddr s)
                   , ("elfSectionSize:",      viaShow $elfSectionSize s)
                   , ("elfSectionLink:",      viaShow $elfSectionLink s)
                   , ("elfSectionInfo:",      viaShow $elfSectionInfo s)
                   , ("elfSectionAddrAlign:", viaShow $elfSectionAddrAlign s)
                   , ("elfSectionEntSize:",   viaShow $elfSectionEntSize s)
                   , ("elfSectionData:",      viaShow $elfSectionData s)
                   ]
        f (n, v) = fillBreak 20 n <+> v
    in
        align $ vsep (f <$> sEntries)

formatSections :: [ElfSection] -> Doc ()
formatSections s = braces $ sep $ punctuate comma $ formatSection <$> s

formatSegment :: ElfSegment -> Doc ()
formatSegment s =
    let sEntries = [ ("elfSegmentType:",     viaShow $ elfSegmentType s)
                   , ("elfSegmentFlags:",    viaShow $ elfSegmentFlags s)
                   , ("elfSegmentVirtAddr:", viaShow $ elfSegmentVirtAddr s)
                   , ("elfSegmentPhysAddr:", viaShow $ elfSegmentPhysAddr s)
                   , ("elfSegmentAlign:",    viaShow $ elfSegmentAlign s)
                   , ("elfSegmentData:",     viaShow $ elfSegmentData s)
                   , ("elfSegmentMemSize:",  viaShow $ elfSegmentMemSize s)
                   ]
        f (n, v) = fillBreak 20 n <+> v
    in
        align $ vsep (f <$> sEntries)

formatSegments :: [ElfSegment] -> Doc ()
formatSegments s = braces $ sep $ punctuate comma $ formatSegment <$> s

formatElf :: Elf -> Doc ()
formatElf elf =
    let topEntries = [ ("elfClass:",      viaShow $ elfClass elf)
                     , ("elfData:",       viaShow $ elfData elf)
                     , ("elfVersion:",    viaShow $ elfVersion elf)
                     , ("elfOSABI:",      viaShow $ elfOSABI elf)
                     , ("elfABIVersion:", viaShow $ elfABIVersion elf)
                     , ("elfType:",       viaShow $ elfType elf)
                     , ("elfMachine:",    viaShow $ elfMachine elf)
                     , ("elfEntry:",      viaShow $ elfEntry elf)
                     , ("elfSections:",   formatSections $ elfSections elf)
                     , ("elfSegments:",   formatSegments $ elfSegments elf)
                     ]
        f (n, v) = fillBreak 15 n <+> v
    in
        vsep (f <$> topEntries)

printElf :: String -> IO ()
printElf fileName = do
    bs <- B.readFile fileName
    putDocW 80 $ (formatElf $ parseElf bs) <> line

main :: IO ()
main = do
    args <- getArgs
    mapM_ printElf args
