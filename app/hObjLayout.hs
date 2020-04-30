{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

import Data.Binary
import Data.Elf
import Data.List
import Numeric.Interval as I
import System.Environment

printSection :: ElfSection -> IO ()
printSection s = putStrLn $ "\t- " ++ (nameToString $ elfSectionName s)

printSegment :: ElfSegment -> IO ()
printSegment p = putStrLn $ "\t- " ++ (show $ elfSegmentType p)

data E = B | E

printElf :: String -> IO ()
printElf fileName = do
    elf <- decodeFile fileName

    putStrLn "sections:"
    mapM_ printSection $ elfSections elf
    putStrLn "segments:"
    mapM_ printSegment $ elfSegments elf

    let
        ElfTableInterval ss _ _ = elfSectionsInterval elf
        ElfTableInterval ps _ _ = elfSegmentsInterval elf
        intervals = [ (elfHeaderInterval elf, "Header")
                    , (ss,                    "Section table")
                    , (ps,                    "Segment table")
                    ]
        f :: (ElfInterval, String) -> [(E, Word64, String)]
        f (i, _) | I.null i    = []
        f (i, s) | otherwise = [(B, inf i, s), (E, sup i, s)]
        endsUnsorted = concat $ fmap f intervals
        fs (_, x, _) = x
        ends = sortOn fs endsUnsorted
        printEnd (B, x, s) = putStrLn $ "^ " ++ show x ++ " " ++ s
        printEnd (E, x, s) = putStrLn $ "v " ++ show x ++ " " ++ s

    mapM_ printEnd ends

main :: IO ()
main = do
    args <- getArgs
    mapM_ printElf args
