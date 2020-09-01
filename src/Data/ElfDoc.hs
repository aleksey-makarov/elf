module Data.ElfDoc ( printHeader
                   , printSection
                   , printSegment
                   ) where

import Data.Text.Prettyprint.Doc as D

import Data.Elf2

printHeader :: Header -> Doc ()
printHeader = undefined

printSection :: SectionXX a -> Doc ()
printSection = undefined

printSegment :: SegmentXX a -> Doc ()
printSegment = undefined
