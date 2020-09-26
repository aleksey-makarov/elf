{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTSyntax #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeFamilyDependencies #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -Wno-unused-top-binds #-}

-- | Data.Elf is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf
    ( module Data.Elf.Generated
    , Elf (..)
    ) where

import Data.Elf.Generated
import Data.Elf.Headers

import Data.Bifunctor
import Data.ByteString.Lazy as BSL
import Data.Either
import Data.List as L
import Data.Singletons
import Data.Singletons.Sigma
import Data.Word
import Numeric.Interval as I
import Numeric.Interval.NonEmpty as INE

data ElfRBuilder (c :: ElfClass)
    = ElfRBuilderHeader
        { erbhHeader :: HeaderXX c
        }
    | ElfRBuilderSection
        { erbsHeader :: SectionXX c
        , erbsN      :: Word32
        }
    | ElfRBuilderSegment
        { erbpHeader :: SegmentXX c
        , erbpN      :: Word32
        , erbpData   :: [(INE.Interval Word16, ElfRBuilder c)]
        }
    | ElfRBuilderSectionTable
    | ElfRBuilderSegmentTable

-- Header can not be empty
headerInterval :: forall a . SingI a => HeaderXX a -> INE.Interval Word64
headerInterval _ = 0 INE.... (fromIntegral $ headerSize $ fromSing $ sing @a) - 1

sectionTableInterval :: SingI a => HeaderXX a -> I.Interval Word64
sectionTableInterval HeaderXX{..} = if (s == 0) then I.empty else o I.... o + s * n - 1
    where
        o = wxxToIntegral hShOff
        s = fromIntegral  hShEntSize
        n = fromIntegral  hShNum

segmentTableInterval :: SingI a => HeaderXX a -> I.Interval Word64
segmentTableInterval HeaderXX{..} = if (s == 0) then I.empty else o I.... o + s * n - 1
    where
        o = wxxToIntegral hPhOff
        s = fromIntegral  hPhEntSize
        n = fromIntegral  hPhNum

sectionInterval :: SingI a => SectionXX a -> I.Interval Word64
sectionInterval SectionXX{..} = if (sType == SHT_NOBITS) || (s == 0) then I.empty else o I.... o + s - 1
    where
        o = wxxToIntegral sOffset
        s = wxxToIntegral sSize

segmentInterval :: SingI a => SegmentXX a -> I.Interval Word64
segmentInterval SegmentXX{..} = if s == 0 then I.empty else o I.... o + s - 1
    where
        o = wxxToIntegral pOffset
        s = wxxToIntegral pFileSize

data LZip a = LZip [a] (Maybe a) [a]

foldInterval :: LZip a -> [a]
foldInterval (LZip l         (Just c) r) = foldInterval $ LZip l  Nothing (c : r)
foldInterval (LZip (l : ls)  Nothing  r) = foldInterval $ LZip ls Nothing (l : r)
foldInterval (LZip []        Nothing  r) = r

findInterval :: Ord t => t -> [(INE.Interval t, a)] -> LZip (INE.Interval t, a)
findInterval e list = findInterval' [] list
    where
        findInterval' l []                              = LZip l Nothing []
        findInterval' l (x : xs) | INE.member e (fst x) = LZip l (Just x) xs
        findInterval' l (x : xs) | e < INE.inf (fst x)  = LZip l Nothing (x : xs)
        findInterval' l (x : xs) | otherwise            = findInterval' xs (x : l)

newtype Elf c = Elf [ElfRBuilder c]

toNonEmpty :: Ord a => I.Interval a -> Maybe (INE.Interval a)
toNonEmpty i | I.null i  = Nothing
toNonEmpty i | otherwise = Just (I.inf i INE.... I.sup i)

factorOutEmptyIntervals :: Ord b => [a] -> (a -> I.Interval b) -> ([a], [(INE.Interval b, a)])
factorOutEmptyIntervals l f = partitionEithers $ fmap ff l
    where
        ff x = case toNonEmpty $ f x of
            Nothing -> Left x
            Just i -> Right (i, x)

-- sort by inf of the intervals
newtype S a b = S { unS :: (INE.Interval a, b) }

instance Eq a => Eq (S a b) where
    (==) (S (x, _)) (S (y, _ )) = INE.inf x == INE.inf y

instance Ord a => Ord (S a b) where
    compare (S (x, _)) (S (y, _ )) = compare (INE.inf x) (INE.inf y)

-- https://gitlab.haskell.org/ghc/ghc/-/issues/11815
zipConsecutives :: [a] -> [(a,a)]
zipConsecutives [] = []
zipConsecutives xs = L.zip xs (L.tail xs)

checkIntervalsDontIntersectPair :: (Show a, Ord a) => ((INE.Interval a, ElfRBuilder b), (INE.Interval a, ElfRBuilder b)) -> Either String ()
checkIntervalsDontIntersectPair (x@(ix, _), y@(iy, _)) = case INE.intersection ix iy of
    Nothing -> Right ()
    Just _ -> Left $ showItem x ++ " and " ++ showItem y ++ " intersect"
    where
        showItem (i, x) = showERB x ++ " (" ++ show i ++ ")"
        showERB ElfRBuilderHeader{..}   = "header"
        showERB ElfRBuilderSection{..}  = "section " ++ show erbsN
        showERB ElfRBuilderSegment{..}  = "segment " ++ show erbpN
        showERB ElfRBuilderSectionTable = "section table"
        showERB ElfRBuilderSegmentTable = "segment table"

checkIntervalsDontIntersect :: (Show a, Ord a) => [(INE.Interval a, ElfRBuilder b)] -> Either String ()
checkIntervalsDontIntersect l = mapM_ checkIntervalsDontIntersectPair $ zipConsecutives l

addSegments :: Ord a => [(INE.Interval a, ElfRBuilder b)] -> (INE.Interval a, ElfRBuilder b) -> (INE.Interval a, ElfRBuilder b)
addSegments = undefined
-- addSegments t@(ti, ElfRBuilderSegment{..}) ts =

addSegment :: Ord a => (INE.Interval a, ElfRBuilder b) -> [(INE.Interval a, ElfRBuilder b)] -> Either String [(INE.Interval a, ElfRBuilder b)]
addSegment t@(ti, ElfRBuilderSegment{..}) ts =
    let
        (LZip l  c'  r ) = findInterval (INE.inf ti) ts
        (LZip l2 c2' r2) = findInterval (INE.sup ti) r
    in
        case (c', c2') of
            (Just c@(ci, _), _)  ->
                if ci `INE.contains` ti then
                    Right $ foldInterval $ LZip l (Just $ addSegments [t] c) r
                else  if ti `INE.contains` ci then
                    case c2' of
                        Nothing -> Right $ foldInterval $ LZip l (Just $ addSegments (c : l2) t) r2
                        Just c2 -> Left $ "@1 " -- ++ intersectMessage t c2
                else
                    Left $ "@2 " -- ++ intersectMessage t c
            (Nothing, Nothing)  -> Right $ foldInterval $ LZip l (Just $ addSegments l2 t) r2
            (Nothing, Just c2@(c2i, _)) ->
                if ti `INE.contains` c2i then
                    Right $ foldInterval $ LZip l (Just $ addSegments (l2 ++ [c2]) t) r2
                else
                    Left $ "@3 " -- ++ intersectMessage t c2

addSegment _ _ = error "can add only segment"

parseElf' :: SingI a => HeaderXX a -> [SectionXX a] -> [SegmentXX a] -> BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf' hdr ss ps _bs = do

    let
        (_emptySections,  isections) = factorOutEmptyIntervals (Prelude.zip [0 .. ] ss) (sectionInterval . snd)
        (_emptySegments, _isegments) = factorOutEmptyIntervals (Prelude.zip [0 .. ] ps) (segmentInterval . snd)

        mkSectionBuilder (n, s) = ElfRBuilderSection s n
        -- mkSegmentBuilder (n, p) = ElfSegment p n
        sections = fmap (second mkSectionBuilder) isections
        header = [(headerInterval hdr, ElfRBuilderHeader hdr)]
        sectionTable = case (toNonEmpty $ sectionTableInterval hdr) of
            Nothing -> []
            Just i -> [(i, ElfRBuilderSectionTable)]
        segmentTable = case (toNonEmpty $ segmentTableInterval hdr) of
            Nothing -> []
            Just i -> [(i, ElfRBuilderSegmentTable)]
        all = fmap unS $ sort $ fmap S $ header ++ sections ++ sectionTable ++ segmentTable

    checkIntervalsDontIntersect all

    undefined

parseElf :: BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf bs = do
    classS :&: HeadersXX (hdr, ss, ps) <- parseHeaders bs
    withSingI classS $ parseElf' hdr ss ps bs
