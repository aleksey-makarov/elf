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
import Data.Interval as I

import Control.Monad
import Control.Monad.Catch
-- import Data.Bifunctor
import Data.ByteString.Char8 as BSC
import Data.ByteString.Lazy as BSL
-- import Data.Either
import Data.Foldable
import Data.Int
import Data.List as L
import Data.Maybe
import Data.Singletons
import Data.Singletons.Sigma
import Data.Word

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

data RBuilderSectionParsedData (c :: ElfClass)
    = NoData
    | SymbolTable [SymbolTableEntryXX c]

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
        , erbsData   :: RBuilderSectionParsedData c
        }
    | RBuilderSegment
        { erbpHeader :: SegmentXX c
        , erbpN      :: Word16
        , erbpData   :: [RBuilder c]
        }

rBuilderInterval :: SingI a => RBuilder a -> Interval Word64
rBuilderInterval RBuilderHeader{..}       = headerInterval erbhHeader
rBuilderInterval RBuilderSectionTable{..} = sectionTableInterval erbstHeader
rBuilderInterval RBuilderSegmentTable{..} = segmentTableInterval erbptHeader
rBuilderInterval RBuilderSection{..}      = sectionInterval erbsHeader
rBuilderInterval RBuilderSegment{..}      = segmentInterval erbpHeader

data LZip a = LZip [a] (Maybe a) [a]

instance Foldable LZip where
    foldMap f (LZip l  (Just c) r) = foldMap f $ LZip l Nothing (c : r)
    foldMap f (LZip l  Nothing  r) = foldMap f $ (L.reverse l) ++ r

findInterval :: (Ord t, Num t) => (a -> Interval t) -> t -> [a] -> LZip a
findInterval f e list = findInterval' [] list
    where
        findInterval' l []                          = LZip l Nothing []
        findInterval' l (x : xs) | e `member` (f x) = LZip l (Just x) xs
        findInterval' l (x : xs) | e < offset (f x) = LZip l Nothing (x : xs)
        findInterval' l (x : xs) | otherwise        = findInterval' (x : l) xs

showRBuilber' :: RBuilder a -> String
showRBuilber' RBuilderHeader{..}        = "header"
showRBuilber' RBuilderSectionTable{..}  = "section table"
showRBuilber' RBuilderSegmentTable{..}  = "segment table"
showRBuilber' RBuilderSection{..}       = "section " ++ show erbsN
showRBuilber' RBuilderSegment{..}       = "segment " ++ show erbpN

showRBuilber :: SingI a => RBuilder a -> String
showRBuilber v = showRBuilber' v ++ " (" ++ (show $ rBuilderInterval v) ++ ")"

-- showERBList :: [ElfRBuilder a] -> String
-- showERBList l = "[" ++ (L.concat $ L.intersperse ", " $ fmap showElfRBuilber l) ++ "]"

intersectMessage :: SingI a => RBuilder a -> RBuilder a -> String
intersectMessage x y = showRBuilber x ++ " and " ++ showRBuilber y ++ " intersect"

addRBuildersToList :: (SingI a, MonadCatch m) => [RBuilder a] -> [RBuilder a] -> m [RBuilder a]
addRBuildersToList newts l = foldM (flip addRBuilder) l newts

addRBuilders :: (SingI a, MonadCatch m) => [RBuilder a] -> RBuilder a -> m (RBuilder a)
addRBuilders [] x = return x
addRBuilders ts RBuilderSegment{..} = do
    d <- addRBuildersToList ts erbpData
    return RBuilderSegment{ erbpData = d, .. }
addRBuilders (x:_) y = $elfError $ intersectMessage x y

addOneRBuilder :: (SingI a, MonadCatch m) => RBuilder a -> RBuilder a -> m (RBuilder a)
addOneRBuilder t@RBuilderSegment{..} c | rBuilderInterval t == rBuilderInterval c = do
    d <- addRBuilder c erbpData
    return RBuilderSegment{ erbpData = d, .. }
addOneRBuilder t RBuilderSegment{..} = do
    d <- addRBuilder t erbpData
    return RBuilderSegment{ erbpData = d, .. }
addOneRBuilder t c = $elfError $ intersectMessage t c

addRBuilder :: (SingI a, MonadCatch m) => RBuilder a -> [RBuilder a] -> m [RBuilder a]
addRBuilder t ts =
    let
        ti  = rBuilderInterval t
        tir = if I.empty ti then offset ti else offset ti + size ti - 1
        (LZip l  c'  r ) = findInterval rBuilderInterval (offset ti) ts
        (LZip l2 c2' r2) = findInterval rBuilderInterval tir         r
    in
        case (c', c2') of
            (Just c, _)  ->
                let
                    ci = rBuilderInterval c
                in if ci `contains` ti then do

                    -- add this:     .........[t____].................................
                    -- or this:      .....[t___________]..............................
                    -- to this list: .....[c___________]......[___]......[________]...
                    c'' <- $addContext' $ addOneRBuilder t c
                    return $ toList $ LZip l (Just c'') r

                else if ti `contains` ci then
                    case c2' of

                        Nothing -> do

                            -- add this:     ......[t__________________________]...................
                            -- to this list: ......[c__]......[l2__]...[l2__].....[________].......
                            c'' <- $addContext' $ addRBuilders (c : l2) t
                            return $ toList $ LZip l (Just c'') r2

                        Just c2 ->
                            let
                                c2i = rBuilderInterval c2
                            in if ti `contains` c2i then do

                                -- add this:     ......[t______________________]........................
                                -- to this list: ......[c_________]......[c2___]......[________]........
                                c'' <- $addContext' $ addRBuilders (c : l2 ++ [c2]) t
                                return $ toList $ LZip l (Just c'') r2
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
                return $ toList $ LZip l (Just c'') r2

            (Nothing, Just c2) ->
                let
                    c2i = rBuilderInterval c2
                in if ti `contains` c2i then do

                    -- add this:     ....[t_________________________________]........
                    -- to this list: ..........[l2__]..[l2__].....[c2_______]........
                    c'' <- $addContext' $ addRBuilders (l2 ++ [c2]) t
                    return $ toList $ LZip l (Just c'') r2

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

mapRBuilderToElf :: SingI a => BSL.ByteString -> BSL.ByteString -> [RBuilder a] -> [Elf a]
mapRBuilderToElf bs strs l = fmap f l
    where
        f RBuilderHeader{ erbhHeader = HeaderXX{..}, .. } =
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
        f RBuilderSectionTable{..} = ElfSectionTable
        f RBuilderSegmentTable{..} = ElfSegmentTable
        f RBuilderSection{ erbsHeader = hdr@SectionXX{..}, ..} =
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
        f RBuilderSegment{ erbpHeader = SegmentXX{..}, ..} =
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
        mkRBuilderSection :: (SingI a, MonadCatch m) => (Word16, SectionXX a) -> m (RBuilder a)
        mkRBuilderSection (n, s) = RBuilderSection s n <$>
            if sectionIsSymbolTable s
                then SymbolTable <$> (parseListA hData $ getSectionData bs s)
                else return NoData

        mkRBuilderSegment :: (SingI a, MonadCatch m) => (Word16, SegmentXX a) -> m (RBuilder a)
        mkRBuilderSegment (n, s) = return $ RBuilderSegment s n []

    sections <- mapM mkRBuilderSection $ tail' $ Prelude.zip [0 .. ] ss
    segments <- mapM mkRBuilderSegment $         Prelude.zip [0 .. ] ps

    let
        firstJust f = listToMaybe . mapMaybe f
        isStringTable RBuilderSection{..} | erbsN == hShStrNdx = Just $ getSectionData bs erbsHeader
        isStringTable _                                        = Nothing
        maybeStringData = firstJust isStringTable sections
        stringData = maybe BSL.empty id maybeStringData

        header            = RBuilderHeader hdr
        maybeSectionTable = if hShNum == 0 then Nothing else  Just $ RBuilderSectionTable hdr
        maybeSegmentTable = if hPhNum == 0 then Nothing else  Just $ RBuilderSegmentTable hdr

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
