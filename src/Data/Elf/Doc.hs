{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Data.Elf.Doc
    ( printHeader
    , printSection
    , printSegment
    , printHeaders
    , printElf
    ) where

import Data.Singletons
import Data.Singletons.Sigma
import Data.Text.Prettyprint.Doc as D
import Data.Word
import Numeric

import Data.Elf
import Data.Elf.Headers

formatPairs :: [(String, Doc a)] -> Doc a
formatPairs ls = align $ vsep $ fmap f ls
    where
        f (n, v) = fill w (pretty n <> ":") <+> v
        w = 1 + (maximum $ fmap (length . fst) ls)

formatList :: [Doc ()] -> Doc ()
formatList = align . vsep . fmap f
    where
        f x = pretty '-' <+> x

padLeadingZeros :: Int -> String -> String
padLeadingZeros n s | length s > n = error "padLeadingZeros args"
padLeadingZeros n s | otherwise = "0x" ++ replicate (n - length s) '0' ++ s

-- printWord8 :: Word8 -> Doc ()
-- printWord8 n = pretty $ padLeadingZeros 2 $ showHex n ""

printWord16 :: Word16 -> Doc ()
printWord16 n = pretty $ padLeadingZeros 4 $ showHex n ""

printWord32 :: Word32 -> Doc ()
printWord32 n = pretty $ padLeadingZeros 8 $ showHex n ""

printWord64 :: Word64 -> Doc ()
printWord64 n = pretty $ padLeadingZeros 16 $ showHex n ""

printWXXS :: Sing a -> WXX a -> Doc ()
printWXXS SELFCLASS32 = printWord32
printWXXS SELFCLASS64 = printWord64

printWXX :: SingI a => WXX a -> Doc ()
printWXX = withSing printWXXS

printHeader :: forall a . SingI a => HeaderXX a -> Doc ()
printHeader HeaderXX{..} =
    formatPairs
        [ ("Class",      viaShow $ fromSing $ sing @a )
        , ("Data",       viaShow hData           ) -- ElfData
        , ("OSABI",      viaShow hOSABI          ) -- ElfOSABI
        , ("ABIVersion", viaShow hABIVersion     ) -- Word8
        , ("Type",       viaShow hType           ) -- ElfType
        , ("Machine",    viaShow hMachine        ) -- ElfMachine
        , ("Entry",      printWXX hEntry         ) -- WXX c
        , ("PhOff",      printWXX hPhOff         ) -- WXX c
        , ("ShOff",      printWXX hShOff         ) -- WXX c
        , ("Flags",      printWord32 hFlags      ) -- Word32
        , ("PhEntSize",  printWord16 hPhEntSize  ) -- Word16
        , ("PhNum",      viaShow hPhNum          ) -- Word16
        , ("ShEntSize",  printWord16  hShEntSize ) -- Word16
        , ("ShNum",      viaShow hShNum          ) -- Word16
        , ("ShStrNdx",   viaShow hShStrNdx       ) -- Word16
        ]

printSection :: SingI a => SectionXX a -> Doc ()
printSection SectionXX{..} =
    formatPairs
        [ ("Name",      viaShow sName       ) -- Word32
        , ("Type",      viaShow sType       ) -- ElfSectionType
        , ("Flags",     printWXX sFlags     ) -- WXX c
        , ("Addr",      printWXX sAddr      ) -- WXX c
        , ("Offset",    printWXX sOffset    ) -- WXX c
        , ("Size",      printWXX sSize      ) -- WXX c
        , ("Link",      viaShow sLink       ) -- Word32
        , ("Info",      viaShow sInfo       ) -- Word32
        , ("AddrAlign", printWXX sAddrAlign ) -- WXX c
        , ("EntSize",   printWXX sEntSize   ) -- WXX c
        ]

printSegment :: SingI a => SegmentXX a -> Doc ()
printSegment SegmentXX{..} =
    formatPairs
        [ ("Type",     viaShow pType      ) -- ElfSegmentType
        , ("Flags",    printWord32 pFlags ) -- Word32
        , ("Offset",   printWXX pOffset   ) -- WXX c
        , ("VirtAddr", printWXX pVirtAddr ) -- WXX c
        , ("PhysAddr", printWXX pPhysAddr ) -- WXX c
        , ("FileSize", printWXX pFileSize ) -- WXX c
        , ("MemSize",  printWXX pMemSize  ) -- WXX c
        , ("Align",    printWXX pAlign    ) -- WXX c
        ]

printHeaders' :: SingI a => HeaderXX a -> [SectionXX a] -> [SegmentXX a] -> Doc ()
printHeaders' hdr ss ps =
    let
        h = printHeader hdr
        s = fmap printSection ss
        p = fmap printSegment ps
    in
        formatPairs
            [ ("Header",   h)
            , ("Sections", formatList s)
            , ("Segments", formatList p)
            ]

printHeaders :: Sigma ElfClass (TyCon1 HeadersXX) -> Doc ()
printHeaders (classS :&: HeadersXX (hdr, ss, ps)) = withSingI classS $ printHeaders' hdr ss ps

formatPairsBlock :: String -> [(String, Doc a)] -> Doc a
formatPairsBlock name pairs = vsep [ pretty name <+> "{", indent 4 $ formatPairs pairs, "}" ]

printElf'' :: forall a . SingI a => Elf a -> Doc ()
printElf'' ElfHeader{..} =
    (formatPairsBlock "header")
        [ ("Class",      viaShow $ fromSing $ sing @a )
        , ("Data",       viaShow ehData       ) -- ElfData
        , ("OSABI",      viaShow ehOSABI      ) -- ElfOSABI
        , ("ABIVersion", viaShow ehABIVersion ) -- Word8
        , ("Type",       viaShow ehType       ) -- ElfType
        , ("Machine",    viaShow ehMachine    ) -- ElfMachine
        , ("Entry",      printWXX ehEntry     ) -- WXX c
        , ("Flags",      printWord32 ehFlags  ) -- Word32
        ]
printElf'' ElfSection{..} =
    (formatPairsBlock $ "section " ++ esName)
        [ ("Type",       viaShow esType       )
        , ("Flags",      printWXX esFlags     )
        , ("Addr",       printWXX esAddr      )
        , ("AddrAlign",  printWXX esAddrAlign )
        , ("EntSize",    printWXX esEntSize   )
        ]
printElf'' ElfSegment{..} =
    (formatPairsBlock "segment")
        [ ("Type",       viaShow epType       )
        , ("Flags",      printWord32 epFlags  )
        , ("VirtAddr",   printWXX epVirtAddr  )
        , ("PhysAddr",   printWXX epPhysAddr  )
        , ("MemSize",    printWXX epMemSize   )
        , ("Align",      printWXX epAlign     )
        , ("Data",       line <> (indent 4 $ printElf' epData) )
    ]
printElf'' ElfSectionTable = "section table"
printElf'' ElfSegmentTable = "segment table"
printElf'' ElfStringSection = "string section"

printElf' :: SingI a => [Elf a] -> Doc ()
printElf' l = align . vsep $ fmap printElf'' l

printElf :: Sigma ElfClass (TyCon1 ElfList) -> Doc ()
printElf (classS :&: ElfList ls) = withSingI classS $ printElf' ls
