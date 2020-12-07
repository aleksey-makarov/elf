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
{-# LANGUAGE StandaloneKindSignatures #-}
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
    , ElfSectionData (..)
    , Elf (..)
    , ElfList (..)
    , Elf'
    , RBuilder (..)
    , parseElf
    , parseRBuilder
    , getSectionData
    , getString
    , elfFindSection
    , elfFindHeader
    , rBuilderInterval
    , serializeElf'
    , serializeElf

    , ElfSymbolTableEntry(..)
    , parseSymbolTable
    ) where

import Data.Elf.Exception
import Data.Elf.Generated
import Data.Elf.Headers
import Data.Interval as I

import Control.Monad
import Control.Monad.Catch
import Control.Monad.State as MS
-- import Data.Bifunctor
import Data.Binary
import Data.Bits as Bin
import Data.ByteString.Char8 as BSC
import Data.ByteString.Lazy as BSL
-- import Data.Either
import Data.Foldable
import Data.Int
-- import Data.Kind
import qualified Data.List as L
import Data.Maybe
import Data.Monoid
import Data.Singletons
import Data.Singletons.Sigma
-- import Data.Word

headerInterval :: forall a . SingI a => HeaderXX a -> Interval Word64
headerInterval _ = I 0 $ headerSize $ fromSing $ sing @a

sectionTableInterval :: SingI a => HeaderXX a -> Interval Word64
sectionTableInterval HeaderXX{..} = I o (s * n)
    where
        o = wxxToIntegral hShOff
        s = fromIntegral  hShEntSize
        n = fromIntegral  hShNum

segmentTableInterval :: SingI a => HeaderXX a -> Interval Word64
segmentTableInterval HeaderXX{..} = I o (s * n)
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

data RBuilder (c :: ElfClass)
    = RBuilderHeader
        { rbhHeader :: HeaderXX c
        }
    | RBuilderSectionTable
        { rbstHeader :: HeaderXX c
        }
    | RBuilderSegmentTable
        { rbptHeader :: HeaderXX c
        }
    | RBuilderSection
        { rbsHeader :: SectionXX c
        , rbsN      :: Word16
        }
    | RBuilderSegment
        { rbpHeader :: SegmentXX c
        , rbpN      :: Word16
        , rbpData   :: [RBuilder c]
        }
    | RBuilderRawData
        { rbrdInterval :: Interval Word64
        }

rBuilderInterval :: SingI a => RBuilder a -> Interval Word64
rBuilderInterval RBuilderHeader{..}       = headerInterval rbhHeader
rBuilderInterval RBuilderSectionTable{..} = sectionTableInterval rbstHeader
rBuilderInterval RBuilderSegmentTable{..} = segmentTableInterval rbptHeader
rBuilderInterval RBuilderSection{..}      = sectionInterval rbsHeader
rBuilderInterval RBuilderSegment{..}      = segmentInterval rbpHeader
rBuilderInterval RBuilderRawData{..}      = rbrdInterval

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
showRBuilber' RBuilderHeader{}       = "header"
showRBuilber' RBuilderSectionTable{} = "section table"
showRBuilber' RBuilderSegmentTable{} = "segment table"
showRBuilber' RBuilderSection{..}    = "section " ++ show rbsN
showRBuilber' RBuilderSegment{..}    = "segment " ++ show rbpN
showRBuilber' RBuilderRawData{}      = "raw data" -- should not be called

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
    d <- addRBuildersToList ts rbpData
    return RBuilderSegment{ rbpData = d, .. }
addRBuilders (x:_) y = $elfError $ intersectMessage x y

addOneRBuilder :: (SingI a, MonadCatch m) => RBuilder a -> RBuilder a -> m (RBuilder a)
addOneRBuilder t@RBuilderSegment{..} c | rBuilderInterval t == rBuilderInterval c = do
    d <- addRBuilder c rbpData
    return RBuilderSegment{ rbpData = d, .. }
addOneRBuilder t RBuilderSegment{..} = do
    d <- addRBuilder t rbpData
    return RBuilderSegment{ rbpData = d, .. }
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
                in if ci `contains` ti then

                    if I.empty ti && offset ti == offset ci
                        then

                            return $ toList $ LZip (t : l) c' r

                        else do

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

data ElfSectionData
    = ElfSectionData BSL.ByteString
    | ElfSectionDataStringTable

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
    | ElfSectionTable
    | ElfSegmentTable
    | ElfSection
        { esName      :: String -- NB: different
        , esType      :: ElfSectionType
        , esFlags     :: WXX c
        , esAddr      :: WXX c
        , esAddrAlign :: WXX c
        , esEntSize   :: WXX c
        , esN         :: Word16
        , esLink      :: Word32
        , esData      :: ElfSectionData
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
    | ElfRawData
        { erData :: BSL.ByteString
        }

-- FIXME MyTree nodeT leafT, bifunctor MyTree, Elf -> split to 6 separate types

-- FIXME: Write GADT record with constrained type: https://stackoverflow.com/questions/21505975/write-gadt-record-with-constrained-type
-- data ElfNodeType = Header | SectionTable | SegmentTable | Section | Segment | Raw
--
-- type Elf :: ElfClass -> ElfNodeType -> Type
-- data Elf c t where
--         ElfHeader ::
--             { ehData       :: ElfData
--             , ehOSABI      :: ElfOSABI
--             , ehABIVersion :: Word8
--             , ehType       :: ElfType
--             , ehMachine    :: ElfMachine
--             , ehEntry      :: WXX c
--             , ehFlags      :: Word32
--             } -> Elf c 'Header
--         ElfSectionTable :: Elf c 'SectionTable
--         ElfSegmentTable :: Elf c 'SegmentTable
--         ElfSection ::
--             { esName      :: String -- NB: different
--             , esType      :: ElfSectionType
--             , esFlags     :: WXX c
--             , esAddr      :: WXX c
--             , esAddrAlign :: WXX c
--             , esEntSize   :: WXX c
--             , esN         :: Word16
--             , esLink      :: Word32
--             , esData      :: ElfSectionData
--             } -> Elf c 'Section
--         ElfSegment ::
--             { epType     :: ElfSegmentType
--             , epFlags    :: Word32
--             , epVirtAddr :: WXX c
--             , epPhysAddr :: WXX c
--             , epMemSize  :: WXX c
--             , epAlign    :: WXX c
--             , epData     :: [Elf c t']
--             } -> Elf c 'Segment
--         ElfRawData ::
--             { erData :: BSL.ByteString
--             } -> Elf c 'Raw
--
-- -- FIXME: ElfSomeNode
-- type ElfNode :: ElfClass -> Type
-- data ElfNode c = forall t' . ElfNode { getElf :: Elf c t' }

foldMapElf :: Monoid m => (Elf a -> m) -> Elf a -> m
foldMapElf f e@ElfSegment{..} = f e <> foldMapElfList f epData
foldMapElf f e = f e

foldMapElfList :: Monoid m => (Elf a -> m) -> [Elf a] -> m
foldMapElfList f l = fold $ fmap (foldMapElf f) l

elfFindSection :: forall a m b . (SingI a, MonadThrow m, Integral b, Show b) => [Elf a] -> b -> m (Elf a)
elfFindSection elfs n = if n == 0
    then $elfError "no section 0"
    else maybe ($elfError $ "no section " ++ show n) return maybeSection
        where
            maybeSection = getFirst $ foldMapElfList f elfs
            f s@ElfSection{..} | esN == fromIntegral n = First $ Just s
            f _ = First Nothing

elfFindHeader :: forall a m . (SingI a, MonadThrow m) => [Elf a] -> m (Elf a)
elfFindHeader elfs = maybe ($elfError $ "no header") return maybeHeader
    where
        maybeHeader = getFirst $ foldMapElfList f elfs
        f h@ElfHeader{} = First $ Just h
        f _ = First Nothing

-- FIXME: Elf' should be just Elf
newtype ElfList c = ElfList [Elf c]
type Elf' = Sigma ElfClass (TyCon1 ElfList)

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

fixRbuilder :: SingI a => RBuilder a -> RBuilder a
fixRbuilder p | I.empty $ rBuilderInterval p = p
fixRbuilder p@RBuilderSegment{..}            = RBuilderSegment{ rbpData = addRaw b newRbpData newE, ..}
    where
        (I b s) = rBuilderInterval p
        -- e, e' and e'' stand for the first occupied byte after the place being fixed
        e = b + s
        fixedRbpData = fmap fixRbuilder rbpData
        (newRbpData, newE) = L.foldr f ([], e) fixedRbpData

        f rb (rbs, e') =
            let
                i@(I o' s') = rBuilderInterval rb
                (e'', b'') = if I.empty i then (o', o') else (o', o' + s')
                rbs' = addRaw b'' rbs e'
            in
                (rb : rbs', e'')

        addRaw :: SingI a => Word64 -> [RBuilder a] -> Word64 -> [RBuilder a]
        addRaw b' rbs e' = case compare b' e' of
            LT -> RBuilderRawData (I b' (e' - b')) : rbs
            EQ -> rbs
            GT -> error "internal error" -- FIXME: add context

fixRbuilder x = x

parseRBuilder :: (MonadCatch m, SingI a) => HeaderXX a -> [SectionXX a] -> [SegmentXX a] -> m [RBuilder a]
parseRBuilder hdr@HeaderXX{..} ss ps = do

    let
        mkRBuilderSection :: (SingI a, MonadCatch m) => (Word16, SectionXX a) -> m (RBuilder a)
        mkRBuilderSection (n, s) = return $ RBuilderSection s n

        mkRBuilderSegment :: (SingI a, MonadCatch m) => (Word16, SegmentXX a) -> m (RBuilder a)
        mkRBuilderSegment (n, s) = return $ RBuilderSegment s n []

    sections <- mapM mkRBuilderSection $ tail' $ Prelude.zip [0 .. ] ss
    segments <- mapM mkRBuilderSegment $         Prelude.zip [0 .. ] ps

    let

        header            = RBuilderHeader hdr
        maybeSectionTable = if hShNum == 0 then Nothing else  Just $ RBuilderSectionTable hdr
        maybeSegmentTable = if hPhNum == 0 then Nothing else  Just $ RBuilderSegmentTable hdr

    fmap fixRbuilder <$> (addRBuilder header
        =<< maybe return addRBuilder maybeSectionTable
        =<< maybe return addRBuilder maybeSegmentTable
        =<< addRBuildersToList segments
        =<< addRBuildersToList sections [])

neighbours :: [a] -> (a -> a -> b) -> [b]
neighbours [] _ = []
neighbours x  f = fmap (uncurry f) $ L.zip x $ L.tail x

parseElf' :: forall a m . (MonadCatch m, SingI a) =>
                                       HeaderXX a ->
                                    [SectionXX a] ->
                                    [SegmentXX a] ->
                                   BSL.ByteString -> m (Elf')
parseElf' hdr@HeaderXX{..} ss ps bs = do

    rbs <- parseRBuilder hdr ss ps

    let
        firstJust f = listToMaybe . mapMaybe f
        isStringTable (n, s) | n == hShStrNdx = Just $ getSectionData bs s
        isStringTable _                       = Nothing
        maybeStringData = firstJust isStringTable $ tail' $ Prelude.zip [0 .. ] ss
        stringData = maybe BSL.empty id maybeStringData

        rBuilderToElf RBuilderHeader{} =
            return ElfHeader
                { ehData       = hData
                , ehOSABI      = hOSABI
                , ehABIVersion = hABIVersion
                , ehType       = hType
                , ehMachine    = hMachine
                , ehEntry      = hEntry
                , ehFlags      = hFlags
                }
        rBuilderToElf RBuilderSectionTable{} =
            return ElfSectionTable
        rBuilderToElf RBuilderSegmentTable{} =
            return ElfSegmentTable
        rBuilderToElf RBuilderSection{ rbsHeader = s@SectionXX{..}, ..} =
            return ElfSection
                { esName      = getString stringData $ fromIntegral sName
                , esType      = sType
                , esFlags     = sFlags
                , esAddr      = sAddr
                , esAddrAlign = sAddrAlign
                , esEntSize   = sEntSize
                , esN         = rbsN
                , esLink      = sLink
                , esData      = if rbsN == hShStrNdx
                    then
                        ElfSectionDataStringTable
                    else
                        ElfSectionData $ getSectionData bs s
                }
        rBuilderToElf RBuilderSegment{ rbpHeader = SegmentXX{..}, ..} = do
            d <- mapM rBuilderToElf rbpData
            return ElfSegment
                { epType     = pType
                , epFlags    = pFlags
                , epVirtAddr = pVirtAddr
                , epPhysAddr = pPhysAddr
                , epMemSize  = pMemSize
                , epAlign    = pAlign
                , epData     = d
                }
        rBuilderToElf RBuilderRawData{ rbrdInterval = I o s } =
            return $ ElfRawData $ cut bs (fromIntegral o) (fromIntegral s)

    el <- mapM rBuilderToElf rbs
    return $ sing :&: ElfList el

parseElf :: MonadCatch m => BSL.ByteString -> m Elf'
parseElf bs = do
    classS :&: HeadersXX (hdr, ss, ps) <- parseHeaders bs
    withSingI classS $ parseElf' hdr ss ps bs

-------------------------------------------------------------------------------
--
-------------------------------------------------------------------------------

data WBuilderData (a :: ElfClass)
    = WBuilderDataHeader
    | WBuilderDataByteStream { wbdData :: BSL.ByteString }
    | WBuilderDataSectionTable
    | WBuilderDataSegmentTable

data WBuilderState (a :: ElfClass) =
    WBuilderState
        { wbsSections         :: [(Word16, SectionXX a)]
        , wbsSegmentsReversed :: [SegmentXX a]
        , wbsDataReversed     :: [WBuilderData a]
        , wbsOffset           :: Word64 -- FIXME shold be WXX
        , wbsPhOff            :: WXX a
        , wbsShOff            :: WXX a
        , wbsShStrNdx         :: Word16
        , wbsStringIndexes    :: [Int64]
        }

wbStateInit :: forall a . SingI a => WBuilderState a
wbStateInit = WBuilderState
    { wbsSections         = []
    , wbsSegmentsReversed = []
    , wbsDataReversed     = []
    , wbsOffset           = 0
    , wbsPhOff            = wxxFromIntegral (0 :: Word32)
    , wbsShOff            = wxxFromIntegral (0 :: Word32)
    , wbsShStrNdx         = 0
    , wbsStringIndexes    = []
    }

zeroXX :: forall a . SingI a => WXX a
zeroXX = wxxFromIntegral (0 :: Word32)

zeroSection :: forall a . SingI a => SectionXX a
zeroSection = SectionXX 0 0 zeroXX zeroXX zeroXX zeroXX 0 0 zeroXX zeroXX

serializeElf' :: forall a m . (SingI a, MonadThrow m) => [Elf a] -> m BSL.ByteString
serializeElf' elfs = do

    (header', hData') <- do
        header <- elfFindHeader elfs
        case header of
            ElfHeader{..} -> return (header, ehData)
            _ -> $elfError "not a header" -- FIXME

    let

        elfClass = fromSing $ sing @a

        sectionN :: Num b => b
        sectionN = getSum $ foldMapElfList f elfs
            where
                f ElfSection{} = Sum 1
                f _ =  Sum 0

        sectionNames :: [String]
        sectionNames = foldMapElfList f elfs
            where
                f ElfSection{..} = [ esName ]
                f _ = []

        (stringTable, stringIndexesReversed) = L.foldl f i sectionNames
            where
                i = (BSL.singleton 0, [0])
                f (st, ir) "" = (st, 0 : ir)
                f (st, ir) s  = (st <> sbs, BSL.length st : ir)
                    where
                        sbs = (BSL.fromStrict $ BSC.pack s) <> BSL.singleton 0

        segmentN :: Num b => b
        segmentN = getSum $ foldMapElfList f elfs
            where
                f ElfSegment{} = Sum 1
                f _ =  Sum 0

        sectionTable :: Bool
        sectionTable = getAny $ foldMapElfList f elfs
            where
                f ElfSectionTable =  Any True
                f _ = Any False

        elf2WBuilder' :: MonadThrow n => Elf a -> WBuilderState a -> n (WBuilderState a)
        elf2WBuilder' ElfHeader{} WBuilderState{..} =
            return WBuilderState
                { wbsDataReversed = WBuilderDataHeader : wbsDataReversed
                , wbsOffset = wbsOffset + headerSize elfClass
                , ..
                }
        elf2WBuilder' ElfSectionTable WBuilderState{..} =
            return WBuilderState
                { wbsDataReversed = WBuilderDataSectionTable : wbsDataReversed
                , wbsOffset = wbsOffset + (sectionN + 1) * sectionSize elfClass
                , wbsShOff = wxxFromIntegral wbsOffset
                , ..
                }
        elf2WBuilder' ElfSegmentTable WBuilderState{..} =
            return WBuilderState
                { wbsDataReversed = WBuilderDataSegmentTable : wbsDataReversed
                , wbsOffset = wbsOffset + segmentN * segmentSize elfClass
                , wbsPhOff = wxxFromIntegral wbsOffset
                , ..
                }
        elf2WBuilder' ElfSection{..} WBuilderState{..} =
            let
                d = case esData of
                    ElfSectionData bs -> bs
                    ElfSectionDataStringTable -> stringTable
                sName = 0                              -- Word32
                sType = esType                         -- ElfSectionType
                sFlags = esFlags                       -- WXX c
                sAddr = esAddr                         -- WXX c
                sOffset = wxxFromIntegral wbsOffset    -- WXX c
                sSize = wxxFromIntegral $ BSL.length d -- WXX c
                sLink = esLink                         -- Word32
                sInfo = 0                              -- Word32 FIXME
                sAddrAlign = esAddrAlign               -- WXX c
                sEntSize = zeroXX                      -- WXX c
            in
                return WBuilderState
                    { wbsSections = (esN, SectionXX{..}) : wbsSections
                    , wbsDataReversed = (WBuilderDataByteStream d) : wbsDataReversed
                    , wbsOffset = wbsOffset + (fromIntegral $ BSL.length d)
                    , ..
                    }
        elf2WBuilder' ElfSegment{..} s = do
            let
                offset = wbsOffset s
            WBuilderState{..} <- execStateT (mapM elf2WBuilder epData) s
            let
                pType = epType
                pFlags = epFlags
                pOffset = wxxFromIntegral offset
                pVirtAddr = epVirtAddr
                pPhysAddr = epPhysAddr
                pFileSize = zeroXX -- FIXME
                pMemSize = epMemSize
                pAlign = epAlign
            return WBuilderState
                { wbsSegmentsReversed = SegmentXX{..} : wbsSegmentsReversed
                , ..
                }
        elf2WBuilder' ElfRawData{..} WBuilderState{..} =
            return WBuilderState
                { wbsDataReversed = (WBuilderDataByteStream erData) : wbsDataReversed
                , wbsOffset = wbsOffset + (fromIntegral $ BSL.length erData)
                , ..
                }

        elf2WBuilder :: (MonadThrow n, MonadState (WBuilderState a) n) => Elf a -> n ()
        elf2WBuilder elf = MS.get >>= elf2WBuilder' elf >>= MS.put

        fixSections :: [(Word16, SectionXX a)] -> m [SectionXX a]
        fixSections ss = do
            when (L.length ss /= sectionN) (error "internal error: L.length ss /= sectionN")
            let
                f (ln, _) (rn, _) = ln `compare` rn
                sorted = L.sortBy f ss
                next (ln, _) (rn, _) = ln + 1 == rn
                checkNeibours = L.all id $ neighbours sorted next

            when (not checkNeibours) ($elfError "sections are not consistent")
            return $ fmap snd sorted

        wbState2ByteString :: WBuilderState a -> m BSL.ByteString
        wbState2ByteString WBuilderState{..} = do

            sections <- fixSections wbsSections

            let
                f WBuilderDataHeader =
                    case header' of
                        ElfHeader{..} ->
                            let
                                hData       = ehData
                                hOSABI      = ehOSABI
                                hABIVersion = ehABIVersion
                                hType       = ehType
                                hMachine    = ehMachine
                                hEntry      = ehEntry
                                hPhOff      = wbsPhOff
                                hShOff      = wbsShOff
                                hFlags      = ehFlags
                                hPhEntSize  = segmentSize elfClass
                                hPhNum      = segmentN
                                hShEntSize  = sectionSize elfClass
                                hShNum      = if sectionTable then sectionN + 1 else 0
                                hShStrNdx   = wbsShStrNdx

                                h :: Header
                                h = sing @ a :&: HeaderXX{..}
                            in
                                encode h
                        _ -> error "this should be ElfHeader" -- FIXME
                f WBuilderDataByteStream {..} = wbdData
                f WBuilderDataSectionTable =
                    serializeListA hData' $ zeroSection : sections
                f WBuilderDataSegmentTable =
                    serializeListA hData' $ L.reverse wbsSegmentsReversed

            return $ foldMap f $ L.reverse wbsDataReversed

    execStateT (mapM elf2WBuilder elfs) wbStateInit{ wbsStringIndexes = L.reverse stringIndexesReversed } >>= wbState2ByteString

serializeElf :: MonadThrow m => Elf' -> m BSL.ByteString
serializeElf (classS :&: ElfList ls) = withSingI classS $ serializeElf' ls

-------------------------------------------------------------------------------
--
-------------------------------------------------------------------------------

-- FIXME: move this to a separate file

data ElfSymbolTableEntry (c :: ElfClass) =
    ElfSymbolTableEntry
        { steName  :: String -- NB: different
        , steBind  :: ElfSymbolBinding
        , steType  :: ElfSymbolType
        , steShNdx :: ElfSectionIndex
        , steValue :: WXX c
        , steSize  :: WXX c
        }

getStringFromData :: BSL.ByteString -> Word32 -> String
getStringFromData stringTable offset = BSC.unpack $ toStrict $ BSL.takeWhile (/= 0) $ BSL.drop (fromIntegral offset) stringTable

mkElfSymbolTableEntry :: SingI a => BSL.ByteString -> SymbolTableEntryXX a -> ElfSymbolTableEntry a
mkElfSymbolTableEntry stringTable SymbolTableEntryXX{..} =
    let
        steName  = getStringFromData stringTable stName
        steBind  = ElfSymbolBinding $ stInfo `shiftR` 4
        steType  = ElfSymbolType $ stInfo .&. 0x0f
        steShNdx = stShNdx
        steValue = stValue
        steSize  = stSize
    in
        ElfSymbolTableEntry{..}

parseSymbolTable :: (MonadThrow m, SingI a) => ElfData -> Elf a -> [Elf a] -> m [ElfSymbolTableEntry a]
parseSymbolTable d ElfSection{ esData = ElfSectionData symbolTable, ..} elfs = do
    section <- elfFindSection elfs esLink
    case section of
        ElfSection{ esData = ElfSectionData stringTable } -> do
            st <- parseListA d symbolTable
            return (mkElfSymbolTableEntry stringTable <$> st)
        _ -> $elfError "not a section" -- FIXME
parseSymbolTable _ _ _ = $elfError "incorrect args to parseSymbolTable" -- FIXME

-- FIXME: serializeSymbolTable
