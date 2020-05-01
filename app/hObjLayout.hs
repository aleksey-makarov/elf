{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

import Data.Binary
import Data.Elf
import Data.List
import Numeric.Interval as I
import System.Environment
import Text.Printf

data E = B | E

data I = S ElfSection [I]
       | P ElfSegment [I]
       | A ElfInterval [I]

printElf :: String -> IO ()
printElf fileName = do

    elf <- decodeFile fileName

    let
        ss = elfSections elf
        ps = elfSegments elf

        printSection :: (Word, ElfSection) -> IO ()
        printSection (i, s) = printf "\t- %-2d %s\n" i (nameToString $ elfSectionName s)

        printSegment :: (Word, ElfSegment) -> IO ()
        printSegment (i, p) = printf "\t- %-2d %s\n" i (show $ elfSegmentType p)

    putStrLn "sections:"
    mapM_ printSection $ zip [0 ..] ss
    putStrLn "segments:"
    mapM_ printSegment $ zip [0 ..] ps

    let
        ElfTableInterval sti _ _ = elfSectionTableInterval elf
        ElfTableInterval pti _ _ = elfSegmentTableInterval elf
        headerIntervals = [ (elfHeaderInterval elf, "Header")
                          , (sti,                    "Section table")
                          , (pti,                    "Segment table")
                          ]

        fSection :: (Word, ElfSection) -> (ElfInterval, String)
        fSection (i, s) = (elfSectionInterval s, "s " ++ show i ++ " " ++ (nameToString $ elfSectionName s))

        fSegment :: (Word, ElfSegment) -> (ElfInterval, String)
        fSegment (i, p) = (elfSegmentInterval p, "p " ++ show i ++ " " ++ (show $ elfSegmentType p))

        sectionIntervals = fmap fSection $ zip [0 ..] ss
        segmentIntervals = fmap fSegment $ zip [0 ..] ps

        intervals = concat [headerIntervals, sectionIntervals, segmentIntervals]

        f :: (ElfInterval, String) -> [(E, Word64, String)]
        f (i, _) | I.null i    = []
        f (i, s) | otherwise = [(B, inf i, s), (E, sup i, s)]

        endsUnsorted = concat $ fmap f intervals

        fs (_, x, _) = x
        ends = sortOn fs endsUnsorted

        printEnd (B, x, s) = printf "^ %016x %s\n" x s
        printEnd (E, x, s) = printf "v %016x %s\n" x s

    mapM_ printEnd ends

main :: IO ()
main = do
    args <- getArgs
    mapM_ printElf args
