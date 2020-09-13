module Data.ElfDoc ( printHeader
                   , printSection
                   , printSegment
                   , printHeaders
                   ) where

import Data.Singletons
import Data.Singletons.Sigma
import Data.Text.Prettyprint.Doc as D

import Data.Elf2

printHeader :: Sing a -> HeaderXX a -> Doc ()
printHeader = undefined

printSection :: Sing a -> SectionXX a -> Doc ()
printSection = undefined

printSegment :: Sing a -> SegmentXX a -> Doc ()
printSegment = undefined

printHeaders' :: Sing a -> HeaderXX a -> [SectionXX a] -> [SegmentXX a] -> Doc ()
printHeaders' classS hdr ss ps = undefined

printHeaders :: Sigma ElfClass (TyCon1 HeadersXX) -> Doc ()
printHeaders (classS :&: HeadersXX (hdr, ss, ps)) = printHeaders' classS hdr ss ps
