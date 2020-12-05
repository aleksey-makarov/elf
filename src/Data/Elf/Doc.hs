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

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC8
import qualified Data.ByteString.Lazy as BSL
import Data.Char
import Data.Int
import qualified Data.List as L
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

printRBuilder :: SingI a => (Word32 -> String) -> [RBuilder a] -> Doc ()
printRBuilder getStr rbs = vsep ldoc

    where

        mapL f (ix, sx, dx) = (ix, f sx, dx)
        getS (_, sx, _) = sx

        longest [] = 0
        longest rbs' = maximum $ fmap (length . getS) rbs'

        padL n s | length s > n = error "incorrect number of pad symbols for `padL`"
        padL n s | otherwise = replicate (n - length s) ' ' ++ s

        equalize l = fmap (mapL (padL l))

        printLine (pos, g, doc) = hsep $ pretty g : printWord32 (fromIntegral pos) : doc
        ls = concat $ map printRBuilder' rbs
        len = longest ls
        ldoc = fmap printLine $ equalize len ls

        printRBuilder' rb = f rb
            where

                i@(I o s) = rBuilderInterval rb

                f RBuilderHeader{} =
                    [ (o,         "┎", ["H"])
                    , (o + s - 1, "┖", [])
                    ]
                f RBuilderSectionTable{ rbstHeader = HeaderXX{..} } =
                    if hShNum == 0
                        then []
                        else
                            [ (o,         "┎", ["ST", parens $ viaShow hShNum])
                            , (o + s - 1, "┖", [])
                            ]
                f RBuilderSegmentTable{ rbptHeader = HeaderXX{..} } =
                    if hPhNum == 0
                        then []
                        else
                            [ (o,         "┎", ["PT", parens $ viaShow hPhNum])
                            , (o + s - 1, "┖", [])
                            ]
                f RBuilderSection{ rbsHeader = SectionXX{..}, ..} =
                    let
                        doc = [ "S" <> viaShow rbsN
                              , dquotes $ pretty $ getStr sName
                              , viaShow sType
                              , viaShow $ splitBits $ ElfSectionFlag $ wxxToIntegral sFlags
                              ]
                    in
                        if empty i
                            then
                                [(o, "-", doc)]
                            else
                                [(o,         "╓", doc)
                                ,(o + s - 1, "╙", [])
                                ]
                f RBuilderSegment{ rbpHeader = SegmentXX{..}, ..} =
                    let
                        doc = [ "P" <> viaShow rbpN
                              , viaShow pType
                              , viaShow $ splitBits $ ElfSegmentFlag $ wxxToIntegral pFlags
                              ]
                    in
                        if empty i
                            then
                                [(o, "-", doc)]
                            else
                                let
                                    xs = concat $ fmap printRBuilder' rbpData
                                    l = longest xs
                                    appendSectionBar = fmap (mapL ('│' : ))
                                    xsf = appendSectionBar $ equalize l xs
                                    b = '┌' : ((replicate l '─'))
                                    e = '└' : ((replicate l '─'))
                                in
                                    [(o,         b, doc)] ++
                                    xsf                         ++
                                    [(o + s - 1, e, [])]
                f RBuilderRawData{} = []
                -- f RBuilderRawData{..} =
                --     let
                --         doc = [ "R" ]
                --     in
                --         [(o,         "╓", doc)
                --         ,(o + s - 1, "╙", [])
                --         ]

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
printElfSymbolTable l = align . vsep $
    case l of
        (e1 : e2 : _ : _) -> [ printElfSymbolTableEntry e1
                             , printElfSymbolTableEntry e2
                             , "..."
                             , printElfSymbolTableEntry $ last l
                             , "total:" <+> viaShow (L.length l)
                             ]
        _ -> fmap printElfSymbolTableEntry l

splitBy :: Int64 -> BSL.ByteString -> [BSL.ByteString]
splitBy n = L.unfoldr f
    where
        f s | BSL.null s = Nothing
        f s | otherwise  = Just $ BSL.splitAt n s

formatChar :: Char -> Doc ()
formatChar c = pretty $ if isAscii c && not (isControl c) then c else '.'

formatHex :: Word8 -> Doc ()
formatHex w = pretty $ case showHex w "" of
    [ d ] -> [ '0', d ]
    ww -> ww

formatBytestringChar :: BS.ByteString -> Doc ()
formatBytestringChar = hcat . L.map formatChar . BC8.unpack

formatBytestringHex :: BS.ByteString -> Doc ()
formatBytestringHex = hsep . L.map formatHex . BS.unpack

formatBytestringLine :: BSL.ByteString -> Doc ()
formatBytestringLine s = (fill (16 * 2 + 15) $ formatBytestringHex sl)
                      <+> pretty '#'
                      <+> formatBytestringChar sl
    where
        sl = BSL.toStrict s

printData :: BSL.ByteString -> Doc ()
printData bs = align $ vsep $
    case splitBy 16 bs of
        (c1 : c2 : _ : _) -> [ formatBytestringLine c1
                             , formatBytestringLine c2
                             , "..."
                             , formatBytestringLine cl
                             , "total:" <+> viaShow (BSL.length bs)
                             ]
        chunks -> L.map formatBytestringLine chunks
    where
        cl = BSL.drop (BSL.length bs - 16) bs

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
    formatPairsBlock ("section" <+> (viaShow esN) <+> (dquotes $ pretty esName))
        [ ("Type",       viaShow esType       )
        , ("Flags",      printWXX esFlags     )
        , ("Addr",       printWXX esAddr      )
        , ("AddrAlign",  printWXX esAddrAlign )
        , ("EntSize",    printWXX esEntSize   )
        , ("Data",       printData esData     )
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
printElf'' ElfRawData{..} =
    formatPairsBlock "raw data"
        [ ("Data",       printData erData)
        ]

printElf' :: SingI a => [Elf a] -> Doc ()
printElf' l = align . vsep $ fmap printElf'' l

printElf :: Sigma ElfClass (TyCon1 ElfList) -> Doc ()
printElf (classS :&: ElfList ls) = withSingI classS $ printElf' ls
