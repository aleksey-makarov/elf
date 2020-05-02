{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeSynonymInstances #-}

import Control.Monad
import Data.Binary
import Data.Elf
import Data.List
import Data.Maybe
import Data.Semigroup
import Numeric.Interval as I
import Numeric.Interval.NonEmpty as INE
import System.Environment
import Text.Printf

import System.IO.Unsafe

data T = S (INE.Interval Word64) Word ElfSection [T]
       | P (INE.Interval Word64) Word ElfSegment [T]
       | A (INE.Interval Word64) String          [T]

class HasInterval a t | a -> t where
    getInterval :: a -> INE.Interval t

instance HasInterval T Word64 where
    getInterval (S i _ _ _) = i
    getInterval (P i _ _ _) = i
    getInterval (A i _ _)   = i

data LZip a = LZip [a] (Maybe a) [a]

findInterval :: (Ord t, HasInterval a t) => t -> [a] -> LZip a
findInterval e list = findInterval' list []
    where
        findInterval' []       l                                = LZip l Nothing []
        findInterval' (x : xs) l | INE.member e (getInterval x) = LZip l (Just x) xs
        findInterval' (x : xs) l | e < INE.inf (getInterval x)  = LZip l Nothing (x : xs)
        findInterval' (x : xs) l | otherwise                    = findInterval' xs (x : l)

foldInterval :: LZip a -> [a]
foldInterval (LZip l         (Just c) r) = foldInterval $ LZip l  Nothing (c : r)
foldInterval (LZip (l : ls)  Nothing  r) = foldInterval $ LZip ls Nothing (l : r)
foldInterval (LZip []        Nothing  r) = r

showId :: T -> String
showId (S i n s _) = "(" ++ show n ++ ": [" ++ show i ++ "] " ++ (nameToString $ elfSectionName s) ++ ")"
showId (P i n p _) = "(" ++ show n ++ ": [" ++ show i ++ "] " ++ (show $ elfSegmentType p)         ++ ")"
showId (A i   s _) = "(" ++             "[" ++ show i ++ "] " ++ s                                 ++ ")"

intersectMessage :: T -> T -> String
intersectMessage a b = showId a ++ " and " ++ showId b ++ " interlap"

addTs :: [T] -> T -> T
addTs ts (S i at s tl) = S i at s $ addTsToList ts tl
addTs ts (P i at p tl) = P i at p $ addTsToList ts tl
addTs ts (A i s    tl) = A i s    $ addTsToList ts tl

addT :: T -> [T] -> [T]
addT t ts =
    let
        ti = getInterval t
        i = INE.inf ti
        s = INE.sup ti
        (LZip l  c  r ) = findInterval i ts
        (LZip l2 c2 r2) = findInterval s r
    in
        case (c, c2) of
            (Just c', _)  ->
                let
                    c'i = getInterval c'
                in
                    -- (unsafePerformIO $ putStrLn $ "s: " ++ show s ++ " I: " ++ (show $ getInterval c')) `seq`
                    if c'i `INE.contains` ti then
                        foldInterval $ LZip l (Just $ addTs [t] c') r
                    else  if ti `INE.contains` c'i then
                        foldInterval $ LZip l (Just $ addTs [c'] t) r
                    else
                        error $ "@2 " ++ intersectMessage t c'
            (Nothing, Nothing)  -> foldInterval $ LZip l (Just $ addTs l2 t) r2
            (Nothing, Just c2') -> error $ "@1 " ++ intersectMessage t c2'

addTsToList :: [T] -> [T] -> [T]
addTsToList newTs l = foldl (flip addT) l newTs

char_S_BEGIN, char_S_MIDDLE, char_P_BEGIN, char_P_MIDDLE, char_P_END, char_H :: Char
char_P_BEGIN = '\x2553'
char_P_MIDDLE = '\x2551'
char_P_END = '\x2559'
char_S_BEGIN = '\x250c'
char_S_MIDDLE = '\x2502'
char_S_END = '\x2514'
char_H = '\x2500'


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
        toNonEmptyUnsafe i = (I.inf i INE.... I.sup i)

        toNonEmpty i | I.null i  = Nothing
        toNonEmpty i | otherwise = Just (I.inf i INE.... I.sup i)

        ElfTableInterval sti _ _ = elfSectionTableInterval elf
        ElfTableInterval pti _ _ = elfSegmentTableInterval elf
        headerIntervals = [ A (toNonEmptyUnsafe $ elfHeaderInterval elf) "Header"        []
                          , A (toNonEmptyUnsafe sti)                     "Section table" []
                          , A (toNonEmptyUnsafe pti)                     "Segment table" []
                          ]

        fSection :: (Word, ElfSection) -> Maybe T
        fSection (i, s) = (\ x -> S x i s []) <$> (toNonEmpty $ elfSectionInterval s)

        fSegment :: (Word, ElfSegment) -> Maybe T
        fSegment (i, p) = (\ x -> P x i p []) <$> (toNonEmpty $ elfSegmentInterval p)

        sectionIntervals = mapMaybe fSection $ zip [0 ..] ss
        segmentIntervals = mapMaybe fSegment $ zip [0 ..] ps

        -- intervals = addTsToList sectionIntervals $ addTsToList headerIntervals $ addTsToList segmentIntervals []
        intervals = addTsToList segmentIntervals []

        tsDepth :: [T] -> Word
        tsDepth l = getMax $ foldr (<>) 0 $ fmap (Max . tDepth) l

        tDepth :: T -> Word
        tDepth (S _ _ _ l) = 1 + tsDepth l
        tDepth (P _ _ _ l) = 1 + tsDepth l
        tDepth (A _   _ l) = 1 + tsDepth l

        printHeader :: [Char] -> Word -> Char -> IO ()
        printHeader p d fst = do
            mapM_ putChar $ reverse p
            let
                n = fromIntegral d - length p
            putChar fst
            when (n > 1) do
                mapM_ putChar $ genericReplicate (n - 1) char_H

        printT :: [Char] -> Word -> T -> IO ()
        printT p w t@(S i at s tl) = do
            printHeader p w char_S_BEGIN
            printf " %016x %s\n" (INE.inf i) $ showId t
            mapM_ (printT (char_S_MIDDLE : p) w) tl
            printHeader p w char_S_END
            printf " %016x %s\n" (INE.sup i) $ showId t
        printT p w t@(P i at _p tl) = do
            printHeader p w char_P_BEGIN
            printf " %016x %s\n" (INE.inf i) $ showId t
            mapM_ (printT (char_P_MIDDLE : p) w) tl
            printHeader p w char_P_END
            printf " %016x %s\n" (INE.sup i) $ showId t
        printT p w t@(A i s    tl) = do
            printHeader p w char_S_BEGIN
            printf " %016x %s\n" (INE.inf i) $ showId t
            mapM_ (printT (char_S_MIDDLE : p) w) tl
            printHeader p w char_S_END
            printf " %016x %s\n" (INE.sup i) $ showId t

        printTs :: [T] -> IO ()
        printTs ts = mapM_ (printT [] (tsDepth ts)) ts

    printTs intervals



main :: IO ()
main = do

    print $ INE.member (23 :: Word64) (0 INE.... 18446744073709551615)

    args <- getArgs
    mapM_ printElf args
