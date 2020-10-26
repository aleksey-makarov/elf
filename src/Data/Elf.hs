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

-- | Data.Elf is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf
    ( module Data.Elf.Generated
    , Elf (..)
    , ElfList (..)
    , ElfSymbolTableEntry (..)
    , parseElf
    , getSectionData
    ) where

import Data.Elf.Exception
import Data.Elf.Generated
import Data.Elf.Headers
import Data.Interval

import Control.Monad
import Control.Monad.Catch
-- import Data.Bifunctor
import Data.ByteString.Char8 as BSC
import Data.ByteString.Lazy as BSL
import Data.Either
import Data.Int
import Data.List as L
import Data.Maybe
import Data.Singletons
import Data.Singletons.Sigma
import Data.Word
-- import Numeric.Interval as I
-- import Numeric.Interval.NonEmpty as INE

headerInterval :: forall a . SingI a => HeaderXX a -> Interval Word64
headerInterval _ = I 0 $ fromIntegral $ headerSize $ fromSing $ sing @a

sectionTableInterval :: SingI a => HeaderXX a -> Interval Word64
sectionTableInterval HeaderXX{..} = I o (o + s * n - 1)
    where
        o = wxxToIntegral hShOff
        s = fromIntegral  hShEntSize
        n = fromIntegral  hShNum

segmentTableInterval :: SingI a => HeaderXX a -> Interval Word64
segmentTableInterval HeaderXX{..} = I o (o + s * n - 1)
    where
        o = wxxToIntegral hPhOff
        s = fromIntegral  hPhEntSize
        n = fromIntegral  hPhNum

sectionInterval :: SingI a => SectionXX a -> Interval Word64
sectionInterval SectionXX{..} = I o s
    where
        o = wxxToIntegral sOffset
        s = if (sType == SHT_NOBITS) then 0 else wxxToIntegral sSize

segmentInterval :: SingI a => SegmentXX a -> Interval Word64
segmentInterval SegmentXX{..} = I o s
    where
        o = wxxToIntegral pOffset
        s = wxxToIntegral pFileSize

data RBuilderSectionData (c :: ElfClass)
    = RBuilderSectionData BSL.ByteString
    | RBuilderSectionDataStringtable
    | RBuilderSectionDataSymbolTable [SymbolTableEntryXX c]

data RBuilder (c :: ElfClass)
    = RBuilderHeader
        { erbhHeader :: HeaderXX c
        }
    | RBuilderSectionTable
        { erbstHeader :: HeaderXX c
        }
    | RBuilderSegmentTable
        { erbptHeader :: HeaderXX c
        }
    | RBuilderSection
        { erbsHeader :: SectionXX c
        , erbsN      :: Word16
        , erbsData   :: RBuilderSectionData c
        }
    | RBuilderSegment
        { erbpHeader :: SegmentXX c
        , erbpN      :: Word16
        , erbpData   :: [RBuilder c]
        }

rBuilderInterval :: SingI a => RBuilder a -> Interval Word64
rBuilderInterval RBuilderHeader{..} = headerInterval erbhHeader
rBuilderInterval RBuilderSectionTable{..} = sectionTableInterval erbhHeader
rBuilderInterval RBuilderSegmentTable{..} = segmentTableInterval erbhHeader
rBuilderInterval RBuilderSection{..} = sectionInterval erbsHeader
rBuilderInterval RBuilderSegment{..} = segmentInterval erbpHeader

data LZip a = LZip [a] (Maybe a) [a]

instance Foldable LZip where
    foldMap f (LZip l  (Just c) r) = foldMap f $ LZip l Nothing (c : r)
    foldMap f (LZip l  Nothing  r) = foldMap f $ (L.reverse l) ++ r

findInterval :: Ord t => (a -> Interval t) -> t -> [a] -> LZip a
findInterval f e list = findInterval' [] list
    where
        findInterval' l []                          = LZip l Nothing []
        findInterval' l (x : xs) | e `member` (f x) = LZip l (Just x) xs
        findInterval' l (x : xs) | e < offset (f x) = LZip l Nothing (x : xs)
        findInterval' l (x : xs) | otherwise        = findInterval' (x : l) xs

-- toNonEmpty :: Ord a => I.Interval a -> Maybe (INE.Interval a)
-- toNonEmpty i | I.null i  = Nothing
-- toNonEmpty i | otherwise = Just (I.inf i INE.... I.sup i)

showRBuilber' :: RBuilder a -> String
showRBuilber' RBuilderHeader{..}        = "header"
showRBuilber' RBuilderSection{..}       = "section " ++ show erbsN
showRBuilber' RBuilderSegment{..}       = "segment " ++ show erbpN
showRBuilber' RBuilderSectionTable{..}  = "section table"
showRBuilber' RBuilderSegmentTable{..}  = "segment table"

showElfRBuilber :: ElfRBuilder a -> String
showElfRBuilber v = showElfRBuilber' v ++ " (" ++ (show $ bInterval v) ++ ")"

showSection :: SingI a => SectionXX a -> String
showSection = undefined

-- showERBList :: [ElfRBuilder a] -> String
-- showERBList l = "[" ++ (L.concat $ L.intersperse ", " $ fmap showElfRBuilber l) ++ "]"

intersectMessage :: ElfRBuilder b -> ElfRBuilder b -> String
intersectMessage x y = showElfRBuilber x ++ " and " ++ showElfRBuilber y ++ " intersect"

addRBuildersToList :: MonadCatch m => [ElfRBuilder b] -> [ElfRBuilder b] -> m [ElfRBuilder b]
addRBuildersToList newts l = foldM (flip addRBuilder) l newts

addRBuilders :: MonadCatch m => [ElfRBuilder b] -> ElfRBuilder b -> m (ElfRBuilder b)
addRBuilders [] x = return x
addRBuilders ts ElfRBuilderSegment{..} = do
    d <- addRBuildersToList ts erbpData
    return ElfRBuilderSegment{ erbpData = d, .. }
addRBuilders (x:_) y = $elfError $ intersectMessage x y

addOneRBuilder :: MonadCatch m => ElfRBuilder b -> ElfRBuilder b -> m (ElfRBuilder b)
addOneRBuilder ElfRBuilderSegment{..} c | bInterval == Data.Elf.bInterval c = do
    d <- addRBuilder c erbpData
    return ElfRBuilderSegment{ erbpData = d, .. }
addOneRBuilder t ElfRBuilderSegment{..} = do
    d <- addRBuilder t erbpData
    return ElfRBuilderSegment{ erbpData = d, .. }
addOneRBuilder t c = $elfError $ intersectMessage t c

addRBuilder :: MonadCatch m => ElfRBuilder b -> [ElfRBuilder b] -> m [ElfRBuilder b]
addRBuilder t ts =
    let
        (LZip l  c'  r ) = findInterval bInterval (INE.inf ti) ts
        (LZip l2 c2' r2) = findInterval bInterval (INE.sup ti) r
        ti = bInterval t
    in
        case (c', c2') of
            (Just c, _)  ->
                let
                    ci = bInterval c
                in if ci `INE.contains` ti then do

                    -- add this:     .........[t____].................................
                    -- or this:      .....[t___________]..............................
                    -- to this list: .....[c___________]......[___]......[________]...
                    c'' <- $addContext' $ addOneRBuilder t c
                    return $ foldInterval $ LZip l (Just c'') r

                else if ti `INE.contains` ci then
                    case c2' of

                        Nothing -> do

                            -- add this:     ......[t__________________________]...................
                            -- to this list: ......[c__]......[l2__]...[l2__].....[________].......
                            c'' <- $addContext' $ addRBuilders (c : l2) t
                            return $ foldInterval $ LZip l (Just c'') r2

                        Just c2 ->
                            let
                                c2i = bInterval c2
                            in if ti `INE.contains` c2i then do

                                -- add this:     ......[t______________________]........................
                                -- to this list: ......[c_________]......[c2___]......[________]........
                                c'' <- $addContext' $ addRBuilders (c : l2 ++ [c2]) t
                                return $ foldInterval $ LZip l (Just c'') r2
                            else

                                -- add this:     ......[t_________________].............................
                                -- to this list: ......[c_________]......[c2___]......[________]........
                                $elfError $ intersectMessage t c2
                else

                    -- add this:     ..........[t________].............................
                    -- to this list: ......[c_________]......[_____]......[________]...
                    $elfError $ intersectMessage t c

            (Nothing, Nothing) -> do

                -- add this:     ....[t___].........................................
                -- or this:      ....[t_________________________]...................
                -- to this list: .............[l2__]...[l2__].....[________]........
                c'' <- $addContext' $ addRBuilders l2 t
                return $ foldInterval $ LZip l (Just c'') r2

            (Nothing, Just c2) ->
                let
                    c2i = bInterval c2
                in if ti `INE.contains` c2i then do

                    -- add this:     ....[t_________________________________]........
                    -- to this list: ..........[l2__]..[l2__].....[c2_______]........
                    c'' <- $addContext' $ addRBuilders (l2 ++ [c2]) t
                    return $ foldInterval $ LZip l (Just c'') r2

                else

                    -- add this:     ....[t_______________________________]..........
                    -- to this list: ..........[l2__]..[l2__].....[c2_______]........
                    $elfError $ intersectMessage t c2

data ElfSymbolTableEntry (c :: ElfClass) =
    ElfSymbolTableEntry
        { steName  :: String -- NB: different
        , steBind  :: ElfSymbolBinding
        , steType  :: ElfSymbolType
        , steShNdx :: ElfSectionIndex
        , steValue :: WXX c
        , steSize  :: WXX c
        }

data Elf (c :: ElfClass)
    = ElfHeader
        { ehData       :: ElfData
        , ehOSABI      :: ElfOSABI
        , ehABIVersion :: Word8
        , ehType       :: ElfType
        , ehMachine    :: ElfMachine
        , ehEntry      :: WXX c
        , ehFlags      :: Word32
        }
    | ElfSection
        { esName      :: String -- NB: different
        , esType      :: ElfSectionType
        , esFlags     :: WXX c
        , esAddr      :: WXX c
        , esAddrAlign :: WXX c
        , esEntSize   :: WXX c
        }
    | ElfSymbolTableSection
        { estName      :: String -- NB: different
        , estType      :: ElfSectionType
        , estFlags     :: WXX c
        , estTable     :: [ElfSymbolTableEntry c]
        }
    | ElfSegment
        { epType     :: ElfSegmentType
        , epFlags    :: Word32
        , epVirtAddr :: WXX c
        , epPhysAddr :: WXX c
        , epMemSize  :: WXX c
        , epAlign    :: WXX c
        , epData     :: [Elf c]
        }
    | ElfSectionTable
    | ElfSegmentTable
    | ElfStringSection

newtype ElfList c = ElfList [Elf c]

mapRBuilderToElf :: SingI a => BSL.ByteString -> BSL.ByteString -> [ElfRBuilder a] -> [Elf a]
mapRBuilderToElf bs strs l = fmap f l
    where
        f ElfRBuilderHeader{ erbhHeader = HeaderXX{..}, .. } =
            let
                ehData       = hData
                ehOSABI      = hOSABI
                ehABIVersion = hABIVersion
                ehType       = hType
                ehMachine    = hMachine
                ehEntry      = hEntry
                ehFlags      = hFlags
            in
                ElfHeader{..}
        f ElfRBuilderSection{ erbsHeader = hdr@SectionXX{..}, ..} =
            if sectionIsSymbolTable hdr
                then
                    let
                        estName      = getString strs (fromIntegral sName)
                        estType      = sType
                        estFlags     = sFlags
                        estTable     = []
                    in
                        ElfSymbolTableSection{..}
                else
                    let
                        esName      = getString strs (fromIntegral sName)
                        esType      = sType
                        esFlags     = sFlags
                        esAddr      = sAddr
                        esAddrAlign = sAddrAlign
                        esEntSize   = sEntSize
                    in
                        ElfSection{..}
        f ElfRBuilderSegment{ erbpHeader = SegmentXX{..}, ..} =
            let
                epType     = pType
                epFlags    = pFlags
                epVirtAddr = pVirtAddr
                epPhysAddr = pPhysAddr
                epMemSize  = pMemSize
                epAlign    = pAlign
                epData     = mapRBuilderToElf bs strs erbpData
            in
                ElfSegment{..}
        f ElfRBuilderSectionTable{..} = ElfSectionTable
        f ElfRBuilderSegmentTable{..} = ElfSegmentTable
        f ElfRBuilderStringSection{..} = ElfStringSection

-- dropFirstFrom :: (a -> Bool) -> [a] -> (Maybe a, [a])
-- dropFirstFrom _ [] = (Nothing, [])
-- dropFirstFrom f (x:xs) = if f x then (Just x, xs) else
--     let
--         (mr, nxs) = dropFirstFrom f xs
--     in
--         (mr, x:nxs)

getString :: BSL.ByteString -> Int64 -> String
getString bs offset = BSC.unpack $ toStrict $ BSL.takeWhile (/= 0) $ BSL.drop offset bs

cut :: BSL.ByteString -> Int64 -> Int64 -> BSL.ByteString
cut content offset size = BSL.take size $ BSL.drop offset content

getSectionData :: SingI a => BSL.ByteString -> SectionXX a -> BSL.ByteString
getSectionData bs SectionXX{..} = cut bs o s
    where
        o = wxxToIntegral sOffset
        s = wxxToIntegral sSize

tail' :: [a] -> [a]
tail' [] = []
tail' (_ : xs) = xs

parseElf' :: (MonadCatch m, SingI a) =>
                          HeaderXX a ->
                       [SectionXX a] ->
                       [SegmentXX a] ->
                      BSL.ByteString -> m (Sigma ElfClass (TyCon1 ElfList))
parseElf' hdr@HeaderXX{..} ss ps bs = do

    let
        isStringTable ElfRBuilderStringSection{..} = Just $ getSectionData bs erbstrsHeader
        isStringTable _ = Nothing

        -- let
        --     findStrSection (n, _) = n == hShStrNdx
        --     (maybeStrSection, ssx) = dropFirstFrom findStrSection (Prelude.zip [0 .. ] ss)

        -- maybeStringSection <- sequence $ dstrsection <$> maybeStrSection

            -- stringSectionToData = getSectionData bs . erbstrsHeader
            -- stringData = maybe BSL.empty stringSectionToData maybeStringSection

        -- FIXME: _emptySections, _emptySegments
        mkRBuilderSection :: (SingI a, MonadCatch m) => (Word16, SectionXX a) -> m (ElfRBuilder a)
        mkRBuilderSection (n, s) = case toNonEmpty $ sectionInterval s of
            Nothing -> $elfError $ "empty section " ++ show n
            Just i ->
                if sectionIsSymbolTable s
                    then
                        ElfRBuilderSymbolTableSection s n i <$> (parseListA hData $ getSectionData bs s)
                    else if n == hShStrNdx
                        then
                            return $ ElfRBuilderStringSection s n i
                        else
                            return $ ElfRBuilderSection s n i

        mkRBuilderSegment :: (SingI a, MonadCatch m) => (Word16, SegmentXX a) -> m (ElfRBuilder a)
        mkRBuilderSegment (n, s) = case toNonEmpty $ segmentInterval s of
            Nothing -> $elfError $ "empty segment " ++ show n
            Just i -> return $ ElfRBuilderSegment s n [] i

        -- dstrsection :: (SingI a, MonadThrow m) => (Word16, SectionXX a) -> m (ElfRBuilder a)
        -- dstrsection (n, s) =
        --     -- FIXME: check that this section is a valid stringsection
        --     case toNonEmpty $ sectionInterval s of
        --         Nothing -> $elfError "empty string section"
        --         Just i -> return $ ElfRBuilderStringSection s n i

    sections <- mapM mkRBuilderSection $ tail' $ Prelude.zip [0 .. ] ss
    segments <- mapM mkRBuilderSegment $         Prelude.zip [0 .. ] ps

    let
        firstJust f = listToMaybe . mapMaybe f
        maybeStringData = firstJust isStringTable sections
        stringData = maybe BSL.empty id maybeStringData
        header = ElfRBuilderHeader hdr $ headerInterval hdr
        maybeSectionTable = ElfRBuilderSectionTable <$> (toNonEmpty $ sectionTableInterval hdr)
        maybeSegmentTable = ElfRBuilderSegmentTable <$> (toNonEmpty $ segmentTableInterval hdr)

    rBuilder  <- addRBuilder header
             =<< maybe return addRBuilder maybeSectionTable
             =<< maybe return addRBuilder maybeSegmentTable
             =<< addRBuildersToList segments
             =<< addRBuildersToList sections []

    return $ sing :&: ElfList (mapRBuilderToElf bs stringData rBuilder)

parseElf :: MonadCatch m => BSL.ByteString -> m (Sigma ElfClass (TyCon1 ElfList))
parseElf bs = do
    classS :&: HeadersXX (hdr, ss, ps) <- parseHeaders bs
    withSingI classS $ parseElf' hdr ss ps bs
