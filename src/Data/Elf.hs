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

import Control.Monad
-- import Data.Bifunctor
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
        , erbpData   :: [(INE.Interval Word64, ElfRBuilder c)]
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

-- https://gitlab.haskell.org/ghc/ghc/-/issues/11815
zipConsecutives :: [a] -> [(a,a)]
zipConsecutives [] = []
zipConsecutives xs = L.zip xs (L.tail xs)

intersectMessage :: Show a => (INE.Interval a, ElfRBuilder b) -> (INE.Interval a, ElfRBuilder b) -> String
intersectMessage x y = showItem x ++ " and " ++ showItem y ++ " intersect"
    where
        showItem (i, v) = showERB v ++ " (" ++ show i ++ ")"
        showERB ElfRBuilderHeader{..}   = "header"
        showERB ElfRBuilderSection{..}  = "section " ++ show erbsN
        showERB ElfRBuilderSegment{..}  = "segment " ++ show erbpN
        showERB ElfRBuilderSectionTable = "section table"
        showERB ElfRBuilderSegmentTable = "segment table"

checkIntervalsDontIntersectPair :: (Show a, Ord a) => ((INE.Interval a, ElfRBuilder b), (INE.Interval a, ElfRBuilder b)) -> Either String ()
checkIntervalsDontIntersectPair (x@(ix, _), y@(iy, _)) = case INE.intersection ix iy of
    Nothing -> Right ()
    Just _ -> Left $ intersectMessage x y ++ " @5"

checkIntervalsDontIntersect :: (Show a, Ord a) => [(INE.Interval a, ElfRBuilder b)] -> Either String ()
checkIntervalsDontIntersect l = mapM_ checkIntervalsDontIntersectPair $ zipConsecutives l

addSegmentsToList :: [(INE.Interval Word64, ElfRBuilder b)] -> [(INE.Interval Word64, ElfRBuilder b)] -> Either String [(INE.Interval Word64, ElfRBuilder b)]
addSegmentsToList newts l = foldM (flip addSegment) l newts

addSegments :: [(INE.Interval Word64, ElfRBuilder b)] -> (INE.Interval Word64, ElfRBuilder b) -> Either String (INE.Interval Word64, ElfRBuilder b)
addSegments [] x = Right x
addSegments ts (it, t@ElfRBuilderSegment{..}) = do
    d <- addSegmentsToList ts erbpData
    return (it, t{ erbpData = d })
addSegments (x:_) y = Left $ intersectMessage x y ++ " @1"

addSegment :: (INE.Interval Word64, ElfRBuilder b) -> [(INE.Interval Word64, ElfRBuilder b)] -> Either String [(INE.Interval Word64, ElfRBuilder b)]
addSegment t@(ti, ElfRBuilderSegment{..}) ts =
    let
        (LZip l  c'  r ) = findInterval (INE.inf ti) ts
        (LZip l2 c2' r2) = findInterval (INE.sup ti) r
    in
        case (c', c2') of
            (Just c@(ci, _), _)  ->

                if ci `INE.contains` ti then do

                    -- add this:     .........[t____].................................
                    -- to this list: .....[c___________]......[___]......[________]...
                    c'' <- addSegments [t] c
                    return $ foldInterval $ LZip l (Just c'') r

                else if ti `INE.contains` ci then
                    case c2' of

                        Nothing -> do

                            -- add this:     ......[t_______]......................................
                            -- or this:      ......[t__________________________]...................
                            -- to this list: ......[c__]......[l2__]...[l2__].....[________].......
                            c'' <- addSegments (c : l2) t
                            return $ foldInterval $ LZip l (Just c'') r2

                        Just c2 ->

                            -- add this:     ......[t_________________].............................
                            -- to this list: ......[c_________]......[c2___]......[________]........
                            Left $ intersectMessage t c2 ++ " @2"
                else

                    -- add this:     ..........[t________].............................
                    -- to this list: ......[c_________]......[_____]......[________]...
                    Left $ intersectMessage t c ++ " @3"

            (Nothing, Nothing) -> do

                -- add this:     ....[t___].........................................
                -- or this:      ....[t_________________________]...................
                -- to this list: .............[l2__]...[l2__].....[________]........
                c'' <- addSegments l2 t
                return $ foldInterval $ LZip l (Just c'') r2

            (Nothing, Just c2@(c2i, _)) ->
                if ti `INE.contains` c2i then do

                    -- add this:     ....[t_________________________________]........
                    -- to this list: ..........[l2__]..[l2__].....[c2_______]........
                    c'' <- addSegments (l2 ++ [c2]) t
                    return $ foldInterval $ LZip l (Just c'') r2

                else

                    -- add this:     ....[t_______________________________]..........
                    -- to this list: ..........[l2__]..[l2__].....[c2_______]........
                    Left $ intersectMessage t c2 ++ " @4"

addSegment _ _ = error "can add only segment"

dsection :: SingI a => (Word32, SectionXX a) -> Either (Word32, SectionXX a) (INE.Interval Word64, ElfRBuilder a)
dsection (n, s) = case toNonEmpty $ sectionInterval s of
    Nothing -> Left (n, s)
    Just i -> Right (i, ElfRBuilderSection s n)

dsegment :: SingI a => (Word32, SegmentXX a) -> Either (Word32, SegmentXX a) (INE.Interval Word64, ElfRBuilder a)
dsegment (n, s) = case toNonEmpty $ segmentInterval s of
    Nothing -> Left (n, s)
    Just i -> Right (i, ElfRBuilderSegment s n [])

parseElf' :: SingI a => HeaderXX a -> [SectionXX a] -> [SegmentXX a] -> BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf' hdr ss ps _bs = do

    let
        (_emptySections, sections) = partitionEithers $ fmap dsection (Prelude.zip [0 .. ] ss)
        (_emptySegments, segments) = partitionEithers $ fmap dsegment (Prelude.zip [0 .. ] ps)

        header = (headerInterval hdr, ElfRBuilderHeader hdr)

        maybeSectionTable = (, ElfRBuilderSectionTable) <$> (toNonEmpty $ sectionTableInterval hdr)
        maybeSegmentTable = (, ElfRBuilderSegmentTable) <$> (toNonEmpty $ segmentTableInterval hdr)

    all  <- addSegment header
        =<< maybe return addSegment maybeSectionTable
        =<< maybe return addSegment maybeSegmentTable
        =<< addSegmentsToList segments
        =<< addSegmentsToList sections []

    -- FIXME: _emptySections, _emptySegments

    undefined

parseElf :: BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf bs = do
    classS :&: HeadersXX (hdr, ss, ps) <- parseHeaders bs
    withSingI classS $ parseElf' hdr ss ps bs
