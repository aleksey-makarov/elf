{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

module Data.ElfDoc ( printHeader
                   , printSection
                   , printSegment
                   , printHeaders
                   ) where

import Numeric
import Data.Singletons
import Data.Singletons.Sigma
import Data.Text.Prettyprint.Doc as D
import Data.Word

import Data.Elf2

formatPairs :: [(Doc a, Doc a)] -> Doc a
formatPairs ls = align $ vsep $ fmap f ls
    where
        f (n, v) = fill 10 (n <> ":") <+> v

-- printWordDoc :: (Integral a, Show a) => a -> Doc ()
-- printWordDoc n = pretty $ "0x" <> showHex n ""

padLeadingZeros :: Int -> String -> String
padLeadingZeros = undefined

printWord8 :: Word8 -> Doc ()
printWord8 n = undefined

printWord16 :: Word16 -> Doc ()
printWord16 n = pretty $ padLeadingZeros 4 $ showHex n ""

printWord32 :: Word32 -> Doc ()
printWord32 n = undefined

printWord64 :: Word64 -> Doc ()
printWord64 n = undefined

printWXX :: forall (a :: ElfClass) . Sing a -> WXX a -> Doc ()
printWXX SELFCLASS32 = printWord32
printWXX SELFCLASS64 = printWord64

printHeader :: Sing a -> HeaderXX a -> Doc ()
printHeader classS HeaderXX{..} =
    formatPairs
        [ ("hData",       viaShow hData          ) -- ElfData
        , ("hOSABI",      viaShow hOSABI         ) -- ElfOSABI
        , ("hABIVersion", viaShow hABIVersion    ) -- Word8
        , ("hType",       viaShow hType          ) -- ElfType
        , ("hMachine",    viaShow hMachine       ) -- ElfMachine
        , ("hEntry",      printWXX classS hEntry ) -- WXX c
        , ("hPhOff",      printWXX classS hPhOff ) -- WXX c
        , ("hShOff",      printWXX classS hShOff ) -- WXX c
        , ("hFlags",      viaShow hFlags         ) -- Word32
        , ("hPhEntSize",  viaShow hPhEntSize     ) -- Word16
        , ("hPhNum",      viaShow hPhNum         ) -- Word16
        , ("hShEntSize",  viaShow hShEntSize     ) -- Word16
        , ("hShNum",      viaShow hShNum         ) -- Word16
        , ("hShStrNdx",   viaShow hShStrNdx      ) -- Word16
        ]

printSection :: Sing a -> SectionXX a -> Doc ()
printSection = undefined

printSegment :: Sing a -> SegmentXX a -> Doc ()
printSegment = undefined

printHeaders' :: Sing a -> HeaderXX a -> [SectionXX a] -> [SegmentXX a] -> Doc ()
printHeaders' classS hdr ss ps = printHeader classS hdr

printHeaders :: Sigma ElfClass (TyCon1 HeadersXX) -> Doc ()
printHeaders (classS :&: HeadersXX (hdr, ss, ps)) = printHeaders' classS hdr ss ps
