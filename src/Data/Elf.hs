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
        , erbpData   :: [ElfRBuilder c]
        }
    | ElfRBuilderSectionTable
--        { estInterval :: Interval Word64
--        }
    | ElfRBuilderSegmentTable
--        { eptInterval :: Interval Word64
--        }

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

parseElf' :: SingI a => HeaderXX a -> [SectionXX a] -> [SegmentXX a] -> BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf' hdr ss ps bs =
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
        all = header ++ sections ++ sectionTable ++ segmentTable
    in
        undefined

parseElf :: BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf bs = do
    classS :&: HeadersXX (hdr, ss, ps) <- parseHeaders bs
    withSingI classS $ parseElf' hdr ss ps bs
