{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleContexts #-}

module Data.Elf.Doc
    ( formatPairs
    , formatList
    , formatPairsBlock
    , printHeader
    , printSection
    , printSegment
    , printHeaders
    , printSymbolTableEntry
    , printRBuilder
    , printElf
    ) where

-- import Data.List as L
import Data.Singletons
import Data.Singletons.Sigma
import Data.Text.Prettyprint.Doc as D
import Data.Word
import Numeric

import Data.Elf
import Data.Elf.Headers
import Data.Interval

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

printWord8 :: Word8 -> Doc ()
printWord8 n = pretty $ padLeadingZeros 2 $ showHex n ""

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

printSection :: SingI a => (Int, (SectionXX a, [SymbolTableEntryXX a])) -> Doc ()
printSection (n, (SectionXX{..}, ss)) =
    formatPairs $
        [ ("N",         viaShow n           )
        , ("Name",      viaShow sName       ) -- Word32
        , ("Type",      viaShow sType       ) -- ElfSectionType
        , ("Flags",     printWXX sFlags     ) -- WXX c
        , ("Addr",      printWXX sAddr      ) -- WXX c
        , ("Offset",    printWXX sOffset    ) -- WXX c
        , ("Size",      printWXX sSize      ) -- WXX c
        , ("Link",      viaShow sLink       ) -- Word32
        , ("Info",      viaShow sInfo       ) -- Word32
        , ("AddrAlign", printWXX sAddrAlign ) -- WXX c
        , ("EntSize",   printWXX sEntSize   ) -- WXX c
        ] ++ if null ss then [] else
            [ ("Symbols", line <> (indent 4 $ formatList $ fmap printSymbolTableEntry ss))
            ]

printSegment :: SingI a => (Int, SegmentXX a) -> Doc ()
printSegment (n, SegmentXX{..}) =
    formatPairs
        [ ("N",        viaShow n          )
        , ("Type",     viaShow pType      ) -- ElfSegmentType
        , ("Flags",    printWord32 pFlags ) -- Word32
        , ("Offset",   printWXX pOffset   ) -- WXX c
        , ("VirtAddr", printWXX pVirtAddr ) -- WXX c
        , ("PhysAddr", printWXX pPhysAddr ) -- WXX c
        , ("FileSize", printWXX pFileSize ) -- WXX c
        , ("MemSize",  printWXX pMemSize  ) -- WXX c
        , ("Align",    printWXX pAlign    ) -- WXX c
        ]

printSymbolTableEntry :: SingI a => SymbolTableEntryXX a -> Doc ()
printSymbolTableEntry SymbolTableEntryXX{..} =
    formatPairs
        [ ("Name",  viaShow stName      )
        , ("Info",  printWord8 stInfo   )
        , ("Other", printWord8 stOther  )
        , ("ShNdx", viaShow stShNdx     )
        , ("Value", printWXX stValue    )
        , ("Size",  printWXX stSize     )
        ]

printHeaders :: SingI a => HeaderXX a -> [(SectionXX a, [SymbolTableEntryXX a])] -> [SegmentXX a] -> Doc ()
printHeaders hdr ss ps =
    let
        h  = printHeader hdr
        s  = fmap printSection (Prelude.zip [0 .. ] ss)
        p  = fmap printSegment (Prelude.zip [0 .. ] ps)
    in
        formatPairs
            [ ("Header",       h)
            , ("Sections",     formatList s)
            , ("Segments",     formatList p)
            ]

--------------------------------------------------------------------
--
--------------------------------------------------------------------

printRBuilder' :: forall a . SingI a => RBuilder a -> [(Word64, String, Doc ())]
printRBuilder' rb = f rb
    where
        i@(I o s) = rBuilderInterval rb
        f RBuilderHeader{..} =
            [ (wxxFromIntegral o, " ", "Hb")
            , (wxxFromIntegral o + s - 1, " ", "He")
            ]
        f RBuilderSectionTable{ erbstHeader = HeaderXX{..}, ..} =
            if hShNum == 0
                then []
                else
                    [ (o, " ", "STb")
                    , (o + s - 1, " ", "STe")
                    ]
        f RBuilderSegmentTable{ erbptHeader = HeaderXX{..}, ..} =
            if hPhNum == 0
                then []
                else
                    [ (o, " ", "PTb")
                    , (o + s - 1, " ", "PTe")
                    ]
        f RBuilderSection{..} =
            if empty i
                then
                    [(wxxFromIntegral o, "-", "S")]
                else
                    [(wxxFromIntegral o, " ", "Sb"), (wxxFromIntegral o + s - 1, " ", "Se")]
        f RBuilderSegment{..} =
            if empty i
                then
                    [(wxxFromIntegral o, "-", "Pb")]
                else
                    let
                        xs = concat $ fmap printRBuilder' erbpData
                    in
                        [(wxxFromIntegral o, " ", "Pb")] ++ xs ++ [(wxxFromIntegral o + s - 1, " ", "Pe")]

printRBuilder :: SingI a => [RBuilder a] -> Doc ()
printRBuilder rbs = vsep ldoc
    where
        printRBuilderList = concat $ map printRBuilder' rbs
        ldoc = fmap f printRBuilderList
        f (pos, g, doc) = printWord64 pos <+> pretty g <+> doc

--------------------------------------------------------------------
--
--------------------------------------------------------------------

formatPairsBlock :: Doc a -> [(String, Doc a)] -> Doc a
formatPairsBlock name pairs = vsep [ name <+> "{", indent 4 $ formatPairs pairs, "}" ]

printElfSymbolTableEntry :: SingI a => ElfSymbolTableEntry a -> Doc ()
printElfSymbolTableEntry ElfSymbolTableEntry{..} =
    formatPairsBlock ("symbol" <+> (dquotes $ pretty steName))
        [ ("Bind",  viaShow steBind   ) -- ElfSymbolBinding
        , ("Type",  viaShow steType   ) -- ElfSymbolType
        , ("ShNdx", viaShow steShNdx  ) -- ElfSectionIndex
        , ("Value", printWXX steValue ) -- WXX c
        , ("Size",  printWXX steSize  ) -- WXX c
        ]

printElfSymbolTable :: SingI a => [ElfSymbolTableEntry a] -> Doc ()
printElfSymbolTable l = align . vsep $ fmap printElfSymbolTableEntry l

printElf'' :: forall a . SingI a => Elf a -> Doc ()
printElf'' ElfHeader{..} =
    formatPairsBlock "header"
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
    formatPairsBlock ("section" <+> (dquotes $ pretty esName))
        [ ("Type",       viaShow esType       )
        , ("Flags",      printWXX esFlags     )
        , ("Addr",       printWXX esAddr      )
        , ("AddrAlign",  printWXX esAddrAlign )
        , ("EntSize",    printWXX esEntSize   )
        ]
printElf'' ElfSymbolTableSection{..} =
    formatPairsBlock ("symbol table section" <+> (dquotes $ pretty estName))
        [ ("Type",       viaShow estType       )
        , ("Flags",      printWXX estFlags     )
        , ("Data",       if null estTable then "" else line <> (indent 4 $ printElfSymbolTable estTable) )
        ]
printElf'' ElfSegment{..} =
    formatPairsBlock "segment"
        [ ("Type",       viaShow epType       )
        , ("Flags",      printWord32 epFlags  )
        , ("VirtAddr",   printWXX epVirtAddr  )
        , ("PhysAddr",   printWXX epPhysAddr  )
        , ("MemSize",    printWXX epMemSize   )
        , ("Align",      printWXX epAlign     )
        , ("Data",       if null epData then "" else line <> (indent 4 $ printElf' epData) )
        ]
printElf'' ElfSectionTable = "section table"
printElf'' ElfSegmentTable = "segment table"
printElf'' ElfStringSection = "string section"

printElf' :: SingI a => [Elf a] -> Doc ()
printElf' l = align . vsep $ fmap printElf'' l

printElf :: Sigma ElfClass (TyCon1 ElfList) -> Doc ()
printElf (classS :&: ElfList ls) = withSingI classS $ printElf' ls
