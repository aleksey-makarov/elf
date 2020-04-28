{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

import Data.Binary
import Data.Elf
import System.Environment

printSection :: ElfSection -> IO ()
printSection s = putStrLn $ "\t- " ++ (nameToString $ elfSectionName s)

printSegment :: ElfSegment -> IO ()
printSegment p = putStrLn $ "\t- " ++ (show $ elfSegmentType p)

printElf :: String -> IO ()
printElf fileName = do
    elf <- decodeFile fileName
    putStrLn "sections:"
    mapM_ printSection $ elfSections elf
    putStrLn "segments:"
    mapM_ printSegment $ elfSegments elf

main :: IO ()
main = do
    args <- getArgs
    mapM_ printElf args
