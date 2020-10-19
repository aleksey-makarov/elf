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
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -Wno-unused-top-binds #-}

-- | Data.Elf is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf.Headers
    ( ElfClass(..)
    , ElfData(..)

    , WXX
    , wxxFromIntegralS
    , wxxFromIntegral
    , wxxToIntegralS
    , wxxToIntegral

    , HeaderXX(..)
    , Header
    , headerSize

    , BList(..)

    , SectionXX(..)
    , SegmentXX(..)
    , SymbolTableEntryXX(..)

    ---------------------------------

    , SElfClass (..)

    , splitBits

    , HeadersXX (..)
    , parseHeaders

    , elfMagic

    , module Data.Elf.Generated) where

-- import Control.Lens hiding (at)
-- import Control.Arrow
import Control.Monad
import Control.Monad.Catch
-- import Control.Monad.State hiding (get, put)
-- import qualified Control.Monad.State as S
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString       as BS
import Data.ByteString.Lazy  as BSL
-- import Data.ByteString.Char8 as BSC
-- import Data.Kind
import Data.List as L
import Data.Singletons.Sigma
import Data.Singletons.TH
-- import Numeric.Interval as I
-- import Numeric.Interval.NonEmpty as INE

-- https://stackoverflow.com/questions/10672981/export-template-haskell-generated-definitions

import Data.Elf.Exception
import Data.Elf.Generated

$(singletons [d|
    data ElfClass
        = ELFCLASS32 -- ^ 32-bit ELF format
        | ELFCLASS64 -- ^ 64-bit ELF format
        deriving (Eq, Show)
    |])

instance Binary ElfClass where
    get = getWord8 >>= getElfClass_
        where
            getElfClass_ 1 = return ELFCLASS32
            getElfClass_ 2 = return ELFCLASS64
            getElfClass_ _ = fail "Invalid ELF class"
    put ELFCLASS32 = putWord8 1
    put ELFCLASS64 = putWord8 2

data ElfData
    = ELFDATA2LSB -- ^ Little-endian ELF format
    | ELFDATA2MSB -- ^ Big-endian ELF format
    deriving (Eq, Show)

instance Binary ElfData where
    get = getWord8 >>= getElfData_
        where
            getElfData_ 1 = return ELFDATA2LSB
            getElfData_ 2 = return ELFDATA2MSB
            getElfData_ _ = fail "Invalid ELF data"
    put ELFDATA2LSB = putWord8 1
    put ELFDATA2MSB = putWord8 2

elfSupportedVersion :: Word8
elfSupportedVersion = 1

-- fromWordXX :: WordXX a -> Word64
-- fromWordXX (W32 w) = fromIntegral w
-- fromWordXX (W64 w) = w
--
-- getWordXX :: Sing a -> ElfData -> Get (WordXX a)
-- getWordXX SELFCLASS32 d = W32 <$> getEndian d
-- getWordXX SELFCLASS64 d = W64 <$> getEndian d

-- at :: (Integral i) => [a] -> i -> Maybe a
-- at (x : _)  0             = Just x
-- at (_ : xs) n | n > 0     = xs `at` (n - 1)
--               | otherwise = Nothing
-- at _        _             = Nothing

-- nameToString :: Maybe BS.ByteString -> String
-- nameToString bs = maybe "" id $ BSC.unpack <$> bs

-- cut :: BS.ByteString -> Int -> Int -> BS.ByteString
-- cut content offset size = BS.take size $ BS.drop offset content

elfMagic :: Be Word32
elfMagic = Be 0x7f454c46 -- "\DELELF"

verify :: (Binary a, Eq a) => String -> a -> Get ()
verify msg orig = do
    a <- get
    when (orig /= a) $ error ("verification failed: " ++ msg)

getTable :: (Binary (Le a), Binary (Be a)) => ElfData -> Word64 -> Word16 -> Word16 -> Get [a]
getTable endianness offset entrySize entryNumber = lookAhead $ do
    skip $ fromIntegral offset
    getTable' entryNumber
    where
        getTable' 0 = return []
        getTable' n = do
            a <- isolate (fromIntegral entrySize) $ getEndian endianness
            (a :) <$> getTable' (n - 1)

getEndian :: (Binary (Le a), Binary (Be a)) => ElfData -> Get a
getEndian ELFDATA2LSB = fromLe <$> get
getEndian ELFDATA2MSB = fromBe <$> get

putEndian :: (Binary (Le a), Binary (Be a)) => ElfData -> a -> Put
putEndian ELFDATA2LSB = put . Le
putEndian ELFDATA2MSB = put . Be

splitBits :: (Num w, FiniteBits w) => w -> [w]
splitBits w = fmap (shiftL 1) $ L.filter (testBit w) $ fmap (subtract 1) [ 1 .. (finiteBitSize w) ]

newtype BList a = BList { fromBList :: [a] }

instance Binary a => Binary (BList a) where
    put (BList (a:as)) = put a >> put (BList as)
    put (BList []) = return ()
    get = do
        e <- isEmpty
        if e then return $ BList [] else do
            a <- get
            (BList as) <- get
            return $ BList $ a : as

--------------------------------------------------------------------------
-- WXX
--------------------------------------------------------------------------

type family WXX (a :: ElfClass) = r | r -> a where
-- type family WXX (a :: ElfClass) where
    WXX 'ELFCLASS64 = Word64
    WXX 'ELFCLASS32 = Word32

-- Can not define
-- instance forall (a :: ElfClass) . SingI a => Binary (Le (WXX a)) where
-- because WXX is a type family
getWXX :: forall (c :: ElfClass) . Sing c -> ElfData -> Get (WXX c)
getWXX SELFCLASS64 ELFDATA2LSB = getWord64le
getWXX SELFCLASS64 ELFDATA2MSB = getWord64be
getWXX SELFCLASS32 ELFDATA2LSB = getWord32le
getWXX SELFCLASS32 ELFDATA2MSB = getWord32be

putWXX :: forall (c :: ElfClass) . Sing c -> ElfData -> WXX c -> Put
putWXX SELFCLASS64 ELFDATA2LSB = putWord64le
putWXX SELFCLASS64 ELFDATA2MSB = putWord64be
putWXX SELFCLASS32 ELFDATA2LSB = putWord32le
putWXX SELFCLASS32 ELFDATA2MSB = putWord32be

wxxFromIntegralS :: Integral i => Sing a -> i -> WXX a
wxxFromIntegralS SELFCLASS64 = fromIntegral
wxxFromIntegralS SELFCLASS32 = fromIntegral

wxxFromIntegral :: (SingI a, Integral i) => i -> WXX a
wxxFromIntegral = wxxFromIntegralS sing

wxxToIntegralS :: Integral i => Sing a -> WXX a -> i
wxxToIntegralS SELFCLASS64 = fromIntegral
wxxToIntegralS SELFCLASS32 = fromIntegral

wxxToIntegral :: (SingI a, Integral i) => WXX a -> i
wxxToIntegral = wxxToIntegralS sing

-- wxxToIntegerS :: Sing a -> WXX a -> Integer
-- wxxToIntegerS SELFCLASS64 = toInteger
-- wxxToIntegerS SELFCLASS32 = toInteger
--
-- wxxToInteger :: SingI a => WXX a -> Integer
-- wxxToInteger = wxxToIntegerS sing

--------------------------------------------------------------------------
-- Header
--------------------------------------------------------------------------

data HeaderXX (c :: ElfClass) =
    HeaderXX
        { hData       :: ElfData
        , hOSABI      :: ElfOSABI
        , hABIVersion :: Word8
        , hType       :: ElfType
        , hMachine    :: ElfMachine
        , hEntry      :: WXX c
        , hPhOff      :: WXX c
        , hShOff      :: WXX c
        , hFlags      :: Word32
        , hPhEntSize  :: Word16
        , hPhNum      :: Word16
        , hShEntSize  :: Word16
        , hShNum      :: Word16
        , hShStrNdx   :: Word16
        }

type Header = Sigma ElfClass (TyCon1 HeaderXX)

headerSize :: ElfClass -> Word16
headerSize ELFCLASS64 = 64
headerSize ELFCLASS32 = 52

getHeader' :: forall (c :: ElfClass) . Sing c -> ElfData -> Get Header
getHeader' classS hData = do

    let
        getE :: (Binary (Le b), Binary (Be b)) => Get b
        getE = getEndian hData

        getWXXE = getWXX classS hData

    verify "version1" elfSupportedVersion
    hOSABI <- get
    hABIVersion <- get
    skip 7
    hType <- getE
    hMachine <- getE

    (hVersion2 :: Word32) <- getE
    when (hVersion2 /= 1) $ error "verification failed: version2"

    hEntry <- getWXXE
    hPhOff <- getWXXE
    hShOff <- getWXXE

    hFlags <- getE
    hSize <- getE
    when (hSize /= (headerSize $ fromSing classS)) $ error "incorrect size of elf header"
    hPhEntSize <- getE
    hPhNum <- getE
    hShEntSize <- getE
    hShNum <- getE
    hShStrNdx <- getE

    return $ classS :&: HeaderXX{..}

getHeader :: Get Header
getHeader = do
    verify "magic" elfMagic
    hClass <- get
    hData <- get
    withSomeSing hClass $ flip getHeader' $ hData

putHeader :: Header -> Put
putHeader (classS :&: HeaderXX{..}) = do

    let
        putE :: (Binary (Le b), Binary (Be b)) => b -> Put
        putE = putEndian hData

        putWXXE = putWXX classS hData

    put elfMagic
    put $ fromSing classS
    put hData
    put elfSupportedVersion
    put hOSABI
    put hABIVersion

    putByteString $ BS.replicate 7 0

    putE hType
    putE hMachine
    putE (1 :: Word32)
    putWXXE hEntry
    putWXXE hPhOff
    putWXXE hShOff
    putE hFlags
    putE $ headerSize $ fromSing classS
    putE hPhEntSize
    putE hPhNum
    putE hShEntSize
    putE hShNum
    putE hShStrNdx

instance Binary Header where
    put = putHeader
    get = getHeader

--------------------------------------------------------------------------
-- Section
--------------------------------------------------------------------------

data SectionXX (c :: ElfClass) =
    SectionXX
        { sName      :: Word32
        , sType      :: ElfSectionType
        , sFlags     :: WXX c
        , sAddr      :: WXX c
        , sOffset    :: WXX c
        , sSize      :: WXX c
        , sLink      :: Word32
        , sInfo      :: Word32
        , sAddrAlign :: WXX c
        , sEntSize   :: WXX c
        }

getSection :: forall (c :: ElfClass) . Sing c -> ElfData -> Get (SectionXX c)
getSection classS hData = do

    let
        getE :: (Binary (Le b), Binary (Be b)) => Get b
        getE = getEndian hData

        getWXXE = getWXX classS hData

    sName <- getE
    sType <- getE
    sFlags <- getWXXE
    sAddr <- getWXXE
    sOffset <- getWXXE
    sSize <- getWXXE
    sLink <- getE
    sInfo <- getE
    sAddrAlign <- getWXXE
    sEntSize <- getWXXE

    return SectionXX {..}

putSection :: forall (c :: ElfClass) . Sing c -> ElfData -> SectionXX c -> Put
putSection  classS hData (SectionXX{..}) = do

    let
        putE :: (Binary (Le b), Binary (Be b)) => b -> Put
        putE = putEndian hData

        putWXXE = putWXX classS hData

    putE sName
    putE sType
    putWXXE sFlags
    putWXXE sAddr
    putWXXE sOffset
    putWXXE sSize
    putE sLink
    putE sInfo
    putWXXE sAddrAlign
    putWXXE sEntSize

instance forall (a :: ElfClass) . SingI a => Binary (Be (SectionXX a)) where
    put = putSection sing ELFDATA2MSB . fromBe
    get = Be <$> getSection sing ELFDATA2MSB

instance forall (a :: ElfClass) . SingI a => Binary (Le (SectionXX a)) where
    put = putSection sing ELFDATA2LSB . fromLe
    get = Le <$> getSection sing ELFDATA2LSB

--------------------------------------------------------------------------
-- Segment
--------------------------------------------------------------------------

data SegmentXX (c :: ElfClass) =
    SegmentXX
        { pType     :: ElfSegmentType
        , pFlags    :: Word32
        , pOffset   :: WXX c
        , pVirtAddr :: WXX c
        , pPhysAddr :: WXX c
        , pFileSize :: WXX c
        , pMemSize  :: WXX c
        , pAlign    :: WXX c
        }

getSegment :: forall (c :: ElfClass) . Sing c -> ElfData -> Get (SegmentXX c)
getSegment SELFCLASS64 hData = do

    let
        getE :: (Binary (Le b), Binary (Be b)) => Get b
        getE = getEndian hData

        getWXXE = getWXX SELFCLASS64 hData

    pType <- getE
    pFlags <- getE
    pOffset <- getWXXE
    pVirtAddr <- getWXXE
    pPhysAddr <- getWXXE
    pFileSize <- getWXXE
    pMemSize <- getWXXE
    pAlign <- getWXXE

    return SegmentXX{..}

getSegment SELFCLASS32 hData = do

    let
        getE :: (Binary (Le b), Binary (Be b)) => Get b
        getE = getEndian hData

        getWXXE = getWXX SELFCLASS32 hData

    pType <- getE
    pOffset <- getWXXE
    pVirtAddr <- getWXXE
    pPhysAddr <- getWXXE
    pFileSize <- getWXXE
    pMemSize <- getWXXE
    pFlags <- getE
    pAlign <- getWXXE

    return SegmentXX{..}

putSegment :: forall (c :: ElfClass) . Sing c -> ElfData -> SegmentXX c -> Put
putSegment SELFCLASS64 hData (SegmentXX{..}) = do
    let
        putE :: (Binary (Le b), Binary (Be b)) => b -> Put
        putE = putEndian hData

        putWXXE = putWXX SELFCLASS64 hData

    putE pType
    putE pFlags
    putWXXE pOffset
    putWXXE pVirtAddr
    putWXXE pPhysAddr
    putWXXE pFileSize
    putWXXE pMemSize
    putWXXE pAlign

putSegment SELFCLASS32 hData (SegmentXX{..}) = do
    let
        putE :: (Binary (Le b), Binary (Be b)) => b -> Put
        putE = putEndian hData

        putWXXE = putWXX SELFCLASS32 hData

    putE pType
    putWXXE pOffset
    putWXXE pVirtAddr
    putWXXE pPhysAddr
    putWXXE pFileSize
    putWXXE pMemSize
    putE pFlags
    putWXXE pAlign


instance forall (a :: ElfClass) . SingI a => Binary (Be (SegmentXX a)) where
    put = putSegment sing ELFDATA2MSB . fromBe
    get = Be <$> getSegment sing ELFDATA2MSB

instance forall (a :: ElfClass) . SingI a => Binary (Le (SegmentXX a)) where
    put = putSegment sing ELFDATA2LSB . fromLe
    get = Le <$> getSegment sing ELFDATA2LSB

--------------------------------------------------------------------------
-- symbol table entry
--------------------------------------------------------------------------

data SymbolTableEntryXX (c :: ElfClass) =
    SymbolTableEntryXX
        { stName  :: Word32
        , stInfo  :: Word8
        , stOther :: Word8
        , stShNdx :: Word16
        , stValue :: WXX c
        , stSize  :: WXX c
        }

getSymbolTableEntry :: forall (c :: ElfClass) . Sing c -> ElfData -> Get (SymbolTableEntryXX c)
getSymbolTableEntry SELFCLASS64 hData = do

    let
        getE :: (Binary (Le b), Binary (Be b)) => Get b
        getE = getEndian hData

        getWXXE = getWXX SELFCLASS64 hData

    stName  <- getE
    stInfo  <- get
    stOther <- get
    stShNdx <- getE
    stValue <- getWXXE
    stSize  <- getWXXE

    return SymbolTableEntryXX{..}

getSymbolTableEntry SELFCLASS32 hData = do

    let
        getE :: (Binary (Le b), Binary (Be b)) => Get b
        getE = getEndian hData

        getWXXE = getWXX SELFCLASS32 hData

    stName  <- getE
    stValue <- getWXXE
    stSize  <- getWXXE
    stInfo  <- get
    stOther <- get
    stShNdx <- getE

    return SymbolTableEntryXX{..}

putSymbolTableEntry :: forall (c :: ElfClass) . Sing c -> ElfData -> SymbolTableEntryXX c -> Put
putSymbolTableEntry SELFCLASS64 hData (SymbolTableEntryXX{..}) = do
    let
        putE :: (Binary (Le b), Binary (Be b)) => b -> Put
        putE = putEndian hData

        putWXXE = putWXX SELFCLASS64 hData

    putE stName
    put stInfo
    put stOther
    putE stShNdx
    putWXXE stValue
    putWXXE stSize

putSymbolTableEntry SELFCLASS32 hData (SymbolTableEntryXX{..}) = do
    let
        putE :: (Binary (Le b), Binary (Be b)) => b -> Put
        putE = putEndian hData

        putWXXE = putWXX SELFCLASS32 hData

    putE stName
    putWXXE stValue
    putWXXE stSize
    put stInfo
    put stOther
    putE stShNdx

instance forall (a :: ElfClass) . SingI a => Binary (Be (SymbolTableEntryXX a)) where
    put = putSymbolTableEntry sing ELFDATA2MSB . fromBe
    get = Be <$> getSymbolTableEntry sing ELFDATA2MSB

instance forall (a :: ElfClass) . SingI a => Binary (Le (SymbolTableEntryXX a)) where
    put = putSymbolTableEntry sing ELFDATA2LSB . fromLe
    get = Le <$> getSymbolTableEntry sing ELFDATA2LSB

--------------------------------------------------------------------------
-- parseHeaders
--------------------------------------------------------------------------

-- FIXME: how to get rid of this? (use some combinators for Sigma)
newtype HeadersXX a = HeadersXX (HeaderXX a, [SectionXX a], [SegmentXX a])
-- type ElfHeadersXX a = (HeaderXX a, SectionXX a, SegmentXX a)

elfDecodeOrFail' :: (Binary a, MonadCatch m) => BSL.ByteString -> m (ByteOffset, a)
elfDecodeOrFail' bs = case decodeOrFail bs of
    Left (_, off, err) -> $elfError $ err ++ " @" ++ show off
    Right (_, off, a) -> return (off, a)

elfDecodeOrFail :: (Binary a, MonadCatch m) => BSL.ByteString -> m a
elfDecodeOrFail bs = snd <$> elfDecodeOrFail' bs

elfDecodeAllOrFail :: (Binary a, MonadCatch m) => BSL.ByteString -> m a
elfDecodeAllOrFail bs = do
    (off, a) <- elfDecodeOrFail' bs
    if off == (BSL.length bs) then return a else $elfError $ "leftover != 0 @" ++ show off

parseListA :: (MonadCatch m, Binary (Le a), Binary (Be a)) => ElfData -> BSL.ByteString -> m [a]
parseListA d bs = case d of
    ELFDATA2LSB -> fmap fromLe <$> fromBList <$> elfDecodeAllOrFail bs
    ELFDATA2MSB -> fmap fromBe <$> fromBList <$> elfDecodeAllOrFail bs

parseHeaders' :: (SingI a, MonadCatch m) => HeaderXX a -> BSL.ByteString -> m (Sigma ElfClass (TyCon1 HeadersXX))
parseHeaders' hxx@HeaderXX{..} bs =
    let
        takeLen off len = BSL.take len $ BSL.drop off bs
        bsSections = takeLen (wxxToIntegral hShOff) (fromIntegral hShEntSize * fromIntegral hShNum)
        bsSegments = takeLen (wxxToIntegral hPhOff) (fromIntegral hPhEntSize * fromIntegral hPhNum)
    in do
        ss <- parseListA hData bsSections
        ps <- parseListA hData bsSegments
        return $ sing :&: HeadersXX (hxx, ss, ps)

parseHeaders :: MonadCatch m => BSL.ByteString -> m (Sigma ElfClass (TyCon1 HeadersXX))
parseHeaders bs = do
    ((classS :&: hxx) :: Header) <- elfDecodeOrFail bs
    withSingI classS $ parseHeaders' hxx bs
