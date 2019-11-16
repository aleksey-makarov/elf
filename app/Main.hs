{-# LANGUAGE OverloadedStrings #-}

import Data.ByteString as B
import Data.ByteString.Char8 as BC8
import Data.Char
import Data.Elf
import Data.Text.Prettyprint.Doc as D
import Data.Text.Prettyprint.Doc.Util
import Data.List as L
import Data.Word
import Numeric
import System.Environment

showHexDoc :: (Integral a, Show a) => a -> Doc ()
showHexDoc n = pretty $ "0x" <> showHex n ""

formatBytestringChar :: ByteString -> Doc ()
formatBytestringChar = hcat . L.map formatChar . BC8.unpack

formatBytestringHex :: ByteString -> Doc ()
formatBytestringHex = hsep . L.map formatHex . B.unpack

formatBytestringLine :: ByteString -> Doc ()
formatBytestringLine s = (fill (16 * 2 + 15) $ formatBytestringHex s)
                      <+> pretty '#'
                      <+> formatBytestringChar s

splitBy :: Int -> ByteString -> [ByteString]
splitBy n = L.unfoldr f
    where
        f s | B.null s = Nothing
        f s | otherwise = Just $ B.splitAt n s

formatChar :: Char -> Doc ()
formatChar c = pretty $ if isAscii c && not (isControl c) then c else '.'

formatHex :: Word8 -> Doc ()
formatHex w = pretty $ case showHex w "" of
    [ d ] -> [ '0', d ]
    ww -> ww

formatBytestring :: ByteString -> Doc ()
formatBytestring = align . vsep . L.map formatBytestringLine . splitBy 16

formatPairs :: [(Doc a, Doc a)] -> Doc a
formatPairs ls = align $ vsep $ fmap f ls
    where
        f (n, v) = fill 20 (n <> ":") <+> v

formatList :: [Doc ()] -> Doc ()
formatList = align . vsep . fmap f
    where
        f x = pretty '-' <+> x

formatSection :: ElfSection -> Doc ()
formatSection s =
    formatPairs [ ("elfSectionName",      viaShow $ elfSectionName s)
                , ("elfSectionType",      viaShow $ elfSectionType s)
                , ("elfSectionFlags",     formatList $ fmap viaShow $ elfSectionFlags s)
                , ("elfSectionAddr",      showHexDoc $ elfSectionAddr s)
                , ("elfSectionSize",      viaShow $ elfSectionSize s)
                , ("elfSectionLink",      viaShow $ elfSectionLink s)
                , ("elfSectionInfo",      viaShow $ elfSectionInfo s)
                , ("elfSectionAddrAlign", viaShow $ elfSectionAddrAlign s)
                , ("elfSectionEntSize",   viaShow $ elfSectionEntSize s)
                , ("elfSectionData",      formatBytestring $ elfSectionData s)
                ]

formatSections :: [ElfSection] -> Doc ()
formatSections s = formatList  $ formatSection <$> s

formatSegment :: ElfSegment -> Doc ()
formatSegment s =
    formatPairs [ ("elfSegmentType",     viaShow $ elfSegmentType s)
                , ("elfSegmentFlags",    formatList $ fmap viaShow $ elfSegmentFlags s)
                , ("elfSegmentVirtAddr", showHexDoc $ elfSegmentVirtAddr s)
                , ("elfSegmentPhysAddr", showHexDoc $ elfSegmentPhysAddr s)
                , ("elfSegmentAlign",    viaShow $ elfSegmentAlign s)
                , ("elfSegmentData",     formatBytestring $ elfSegmentData s)
                , ("elfSegmentMemSize",  viaShow $ elfSegmentMemSize s)
                ]

formatSegments :: [ElfSegment] -> Doc ()
formatSegments s = formatList $ formatSegment <$> s

formatElf :: Elf -> Doc ()
formatElf elf =
    formatPairs [ ("elfClass",      viaShow $ elfClass elf)
                , ("elfData",       viaShow $ elfData elf)
                , ("elfVersion",    viaShow $ elfVersion elf)
                , ("elfOSABI",      viaShow $ elfOSABI elf)
                , ("elfABIVersion", viaShow $ elfABIVersion elf)
                , ("elfType",       viaShow $ elfType elf)
                , ("elfMachine",    viaShow $ elfMachine elf)
                , ("elfEntry",      showHexDoc $ elfEntry elf)
                , ("elfSections",   formatSections $ elfSections elf)
                , ("elfSegments",   formatSegments $ elfSegments elf)
                ]

printElf :: String -> IO ()
printElf fileName = do
    bs <- B.readFile fileName
    putDocW 80 $ (formatElf $ parseElf bs) <> line

main :: IO ()
main = do
    args <- getArgs
    mapM_ printElf args
