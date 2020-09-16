{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

module Data.Elf.Doc
    ( printHeader
    , printSection
    , printSegment
    , printHeaders
    ) where

import Data.Singletons
import Data.Singletons.Sigma
import Data.Text.Prettyprint.Doc as D
import Data.Word
import Numeric

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

printWXXS :: forall (a :: ElfClass) . Sing a -> WXX a -> Doc ()
printWXXS SELFCLASS32 = printWord32
printWXXS SELFCLASS64 = printWord64

printWXX :: SingI a => WXX a -> Doc ()
printWXX = withSing printWXXS

printHeader :: SingI a => HeaderXX a -> Doc ()
printHeader HeaderXX{..} =
    formatPairs
        [ ("hData",       viaShow hData           ) -- ElfData
        , ("hOSABI",      viaShow hOSABI          ) -- ElfOSABI
        , ("hABIVersion", viaShow hABIVersion     ) -- Word8
        , ("hType",       viaShow hType           ) -- ElfType
        , ("hMachine",    viaShow hMachine        ) -- ElfMachine
        , ("hEntry",      printWXX hEntry         ) -- WXX c
        , ("hPhOff",      printWXX hPhOff         ) -- WXX c
        , ("hShOff",      printWXX hShOff         ) -- WXX c
        , ("hFlags",      printWord32 hFlags      ) -- Word32
        , ("hPhEntSize",  printWord16 hPhEntSize  ) -- Word16
        , ("hPhNum",      viaShow hPhNum          ) -- Word16
        , ("hShEntSize",  printWord16  hShEntSize ) -- Word16
        , ("hShNum",      viaShow hShNum          ) -- Word16
        , ("hShStrNdx",   viaShow hShStrNdx       ) -- Word16
        ]

printSection :: SingI a => SectionXX a -> Doc ()
printSection SectionXX{..} =
    formatPairs
        [ ("sName",      viaShow sName       ) -- Word32
        , ("sType",      viaShow sType       ) -- ElfSectionType
        , ("sFlags",     printWXX sFlags     ) -- WXX c
        , ("sAddr",      printWXX sAddr      ) -- WXX c
        , ("sOffset",    printWXX sOffset    ) -- WXX c
        , ("sSize",      printWXX sSize      ) -- WXX c
        , ("sLink",      viaShow sLink       ) -- Word32
        , ("sInfo",      viaShow sInfo       ) -- Word32
        , ("sAddrAlign", printWXX sAddrAlign ) -- WXX c
        , ("sEntSize",   printWXX sEntSize   ) -- WXX c
        ]

printSegment :: SingI a => SegmentXX a -> Doc ()
printSegment SegmentXX{..} =
    formatPairs
        [ ("pType",     viaShow pType      ) -- ElfSegmentType
        , ("pFlags",    printWord32 pFlags ) -- Word32
        , ("pOffset",   printWXX pOffset   ) -- WXX c
        , ("pVirtAddr", printWXX pVirtAddr ) -- WXX c
        , ("pPhysAddr", printWXX pPhysAddr ) -- WXX c
        , ("pFileSize", printWXX pFileSize ) -- WXX c
        , ("pMemSize",  printWXX pMemSize  ) -- WXX c
        , ("pAlign",    printWXX pAlign    ) -- WXX c
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
