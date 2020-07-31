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
module Data.Elf ( ElfClass(..)
                , ElfData(..)

                , SElfClass (..)

                , Elf
                , elfClass
                , elfData
                , elfVersion
                , elfOSABI
                , elfABIVersion
                , elfType
                , elfMachine
                , elfEntry
                , elfSections
                , elfSegments

                , ElfTableInterval(..)
                , elfHeaderInterval
                , elfSectionTableInterval
                , elfSegmentTableInterval
                , elfSectionInterval
                , elfSegmentInterval

                , ElfSection
                , elfSectionName
                , elfSectionType
                , elfSectionFlags
                , elfSectionAddr
                , elfSectionSize
                , elfSectionLink
                , elfSectionInfo
                , elfSectionAddrAlign
                , elfSectionEntSize
                , elfSectionData

                , ElfSegment
                , elfSegmentType
                , elfSegmentFlags
                , elfSegmentVirtAddr
                , elfSegmentPhysAddr
                , elfSegmentAlign
                , elfSegmentData
                , elfSegmentMemSize

                , splitBits
                , nameToString

                , ElfSymbolTableEntry
                , steName
                , steType
                , steBind
                , steIndex
                , steValue
                , steSize
                , steOther
                , elfParseSymbolTable

                , ElfBuilderT
                , mkHeader
                , mkSectionTable
                , mkSegmentTable
                , mkSection
                , mkSegment
                , mkElf

                , module Data.Elf.Generated) where

import Control.Lens hiding (at)
import Control.Monad
import Control.Monad.State hiding (get, put)
import qualified Control.Monad.State as S
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import Data.ByteString       as BS
import Data.ByteString.Lazy  as BSL
import Data.ByteString.Char8 as BSC
import Data.Kind
import Data.List as L
import Data.Singletons.Sigma
import Data.Singletons.TH
import Numeric.Interval as I
import Numeric.Interval.NonEmpty as INE

-- https://stackoverflow.com/questions/10672981/export-template-haskell-generated-definitions

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

data ElfSectionXX (c :: ElfClass) where
    ElfSection64 ::
        { s64Name      :: Word32
        , s64Type      :: ElfSectionType    -- ^ Identifies the type of the section.
        , s64Flags     :: Word64            -- ^ Identifies the attributes of the section.
        , s64Addr      :: Word64            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
        , s64Offset    :: Word64
        , s64Size      :: Word64            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
        , s64Link      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
        , s64Info      :: Word32            -- ^ Contains extra information for the index, depending on type.
        , s64AddrAlign :: Word64            -- ^ Contains the required alignment of the section. Must be a power of two.
        , s64EntSize   :: Word64            -- ^ Size of entries if section has a table.
        } -> ElfSectionXX 'ELFCLASS64
    ElfSection32 ::
        { s32Name      :: Word32
        , s32Type      :: ElfSectionType    -- ^ Identifies the type of the section.
        , s32Flags     :: Word32            -- ^ Identifies the attributes of the section.
        , s32Addr      :: Word32            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
        , s32Offset    :: Word32
        , s32Size      :: Word32            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
        , s32Link      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
        , s32Info      :: Word32            -- ^ Contains extra information for the index, depending on type.
        , s32AddrAlign :: Word32            -- ^ Contains the required alignment of the section. Must be a power of two.
        , s32EntSize   :: Word32            -- ^ Size of entries if section has a table.
        } -> ElfSectionXX 'ELFCLASS32

instance forall (a :: ElfClass) . SingI a => Binary (Be (ElfSectionXX a)) where
    put = undefined
    get = Be <$> getElfSectionXX sing (getEndian ELFDATA2MSB)

instance forall (a :: ElfClass) . SingI a => Binary (Le (ElfSectionXX a)) where
    put = undefined
    get = Le <$> getElfSectionXX sing (getEndian ELFDATA2LSB)

data ElfSection = forall a . ElfSection (ElfXX a) (ElfSectionXX a)

data ElfSegmentXX (c :: ElfClass) where
    ElfSegment64 ::
        { p64Type     :: ElfSegmentType   -- ^ Segment type
        , p64Flags    :: Word32           -- ^ Segment flags
        , p64Offset   :: Word64
        , p64VirtAddr :: Word64           -- ^ Virtual address for the segment
        , p64PhysAddr :: Word64           -- ^ Physical address for the segment
        , p64FileSize :: Word64
        , p64MemSize  :: Word64           -- ^ Size in memory  (may be larger then the segment's data)
        , p64Align    :: Word64           -- ^ Segment alignment
        } -> ElfSegmentXX 'ELFCLASS64
    ElfSegment32 ::
        { p32Type     :: ElfSegmentType   -- ^ Segment type
        , p32Offset   :: Word32
        , p32VirtAddr :: Word32           -- ^ Virtual address for the segment
        , p32PhysAddr :: Word32           -- ^ Physical address for the segment
        , p32FileSize :: Word32
        , p32MemSize  :: Word32           -- ^ Size in memory  (may be larger then the segment's data)
        , p32Flags    :: Word32           -- ^ Segment flags
        , p32Align    :: Word32           -- ^ Segment alignment
        } -> ElfSegmentXX 'ELFCLASS32

instance forall (a :: ElfClass) . SingI a => Binary (Be (ElfSegmentXX a)) where
    put = undefined
    get = Be <$> getElfSegmentXX sing (getEndian ELFDATA2MSB)

instance forall (a :: ElfClass) . SingI a => Binary (Le (ElfSegmentXX a)) where
    put = undefined
    get = Le <$> getElfSegmentXX sing (getEndian ELFDATA2LSB)

data ElfSegment = forall a . ElfSegment (ElfXX a) (ElfSegmentXX a)

data WordXX (a :: ElfClass) :: Type where
    W32 :: Word32 -> WordXX 'ELFCLASS32
    W64 :: Word64 -> WordXX 'ELFCLASS64

instance forall (a :: ElfClass) . SingI a => Binary (Be (WordXX a)) where
    put = undefined
    get = Be <$> getWordXX sing ELFDATA2MSB

instance forall (a :: ElfClass) . SingI a => Binary (Le (WordXX a)) where
    put = undefined
    get = Le <$> getWordXX sing ELFDATA2LSB

fromWordXX :: WordXX a -> Word64
fromWordXX (W32 w) = fromIntegral w
fromWordXX (W64 w) = w

getWordXX :: Sing a -> ElfData -> Get (WordXX a)
getWordXX SELFCLASS32 d = W32 <$> getEndian d
getWordXX SELFCLASS64 d = W64 <$> getEndian d

data ElfXX (c :: ElfClass) =
    ElfXX
        { exxData       :: ElfData       -- ^ Identifies the data encoding of the object file (endianness).
        , exxOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
        , exxABIVersion :: Word8         -- ^ Identifies the ABI version for which the object is prepared.
        , exxType       :: ElfType       -- ^ Identifies the object file type.
        , exxMachine    :: ElfMachine    -- ^ Identifies the target architecture.
        , exxEntry      :: WordXX c
        , exxPhOff      :: WordXX c
        , exxShOff      :: WordXX c
        , exxFlags      :: Word32
        , exxHSize      :: Word16
        , exxPhEntSize  :: Word16
        , exxPhNum      :: Word16
        , exxShEntSize  :: Word16
        , exxShNum      :: Word16
        , exxShStrNdx   :: ElfSectionIndex
        , exxSegments   :: [ElfSegmentXX c]
        , exxSections   :: [ElfSectionXX c]
        , exxContent    :: BS.ByteString
        }

type Elf = Sigma ElfClass (TyCon1 ElfXX)

instance Binary Elf where
    put (_ :&: ElfXX{..}) = putByteString exxContent
    get = getElf

elfSupportedVersion :: Word8
elfSupportedVersion = 1

elfVersion :: Elf -> Word8
elfVersion _ = elfSupportedVersion

elfClass :: Elf -> ElfClass
elfClass (c :&: _) = fromSing c

elfData :: Elf -> ElfData
elfData (_ :&: ElfXX{..}) = exxData

elfOSABI :: Elf -> ElfOSABI
elfOSABI (_ :&: ElfXX{..}) = exxOSABI

elfABIVersion :: Elf -> Word8
elfABIVersion (_ :&: ElfXX{..}) = exxABIVersion

elfMachine :: Elf -> ElfMachine
elfMachine (_ :&: ElfXX{..}) = exxMachine

elfType :: Elf -> ElfType
elfType (_ :&: ElfXX{..}) = exxType

elfEntry :: Elf -> Word64
elfEntry (_ :&: ElfXX{..}) = fromWordXX exxEntry

elfSections :: Elf -> [ElfSection]
elfSections (_ :&: elfXX@ElfXX{..}) = fmap (ElfSection elfXX) exxSections

elfSegments :: Elf -> [ElfSegment]
elfSegments (_ :&: elfXX@ElfXX{..}) = fmap (ElfSegment elfXX) exxSegments

elfHeaderInterval :: Elf -> INE.Interval Word64
elfHeaderInterval (_ :&: ElfXX{..}) = 0 INE.... fromIntegral exxHSize - 1

data ElfTableInterval = ElfTableInterval { interval :: INE.Interval Word64
                                         , size     :: Word16
                                         , num      :: Word16
                                         }

elfSectionTableInterval :: Elf -> Maybe ElfTableInterval
elfSectionTableInterval (_ :&: ElfXX{..}) = if (s == 0) then Nothing else Just $ ElfTableInterval i exxShEntSize exxShNum
    where
        o = fromWordXX   exxShOff
        s = fromIntegral exxShEntSize
        n = fromIntegral exxShNum
        i = o INE.... o + s * n - 1

elfSegmentTableInterval :: Elf -> Maybe ElfTableInterval
elfSegmentTableInterval (_ :&: ElfXX{..}) =  if (s == 0) then Nothing else Just $ ElfTableInterval i exxPhEntSize exxPhNum
    where
        o = fromWordXX   exxPhOff
        s = fromIntegral exxPhEntSize
        n = fromIntegral exxPhNum
        i = o INE.... o + s * n - 1

at :: (Integral i) => [a] -> i -> Maybe a
at (x : _)  0             = Just x
at (_ : xs) n | n > 0     = xs `at` (n - 1)
              | otherwise = Nothing
at _        _             = Nothing

nameToString :: Maybe BS.ByteString -> String
nameToString bs = maybe "" id $ BSC.unpack <$> bs

getStringSectionData :: ElfXX a -> Word32 -> Maybe BS.ByteString
getStringSectionData elfXX@ElfXX{..} sectionIndex = elfSectionData' elfXX <$> exxSections `at` sectionIndex

getString :: ElfXX a -> Word32 -> Word32 -> Maybe BS.ByteString
getString elfXX sectionIndex offset = BS.takeWhile (/= 0) <$> BS.drop (fromIntegral offset) <$> getStringSectionData elfXX sectionIndex

getSectionIndex :: ElfSectionIndex -> Maybe Word32
getSectionIndex SHN_Undef           = Nothing
getSectionIndex x | x >= SHN_LoProc = Nothing
getSectionIndex (SHN_EXT x)         = Just $ fromIntegral x
getSectionIndex _                   = Nothing

-- FIXME: export the index of the string, not the name
elfSectionName :: ElfSection -> Maybe BS.ByteString -- ^ Identifies the name of the section.
elfSectionName (ElfSection elfXX@ElfXX{..} ElfSection64{..}) = getSectionIndex exxShStrNdx >>= \ i -> getString elfXX i s64Name
elfSectionName (ElfSection elfXX@ElfXX{..} ElfSection32{..}) = getSectionIndex exxShStrNdx >>= \ i -> getString elfXX i s32Name

elfSectionType :: ElfSection -> ElfSectionType -- ^ Identifies the name of the section.
elfSectionType (ElfSection _ ElfSection64{..}) = s64Type
elfSectionType (ElfSection _ ElfSection32{..}) = s32Type

elfSectionFlags :: ElfSection -> ElfSectionFlag -- ^ Identifies the attributes of the section.
elfSectionFlags (ElfSection _ ElfSection64{..}) = ElfSectionFlag s64Flags
elfSectionFlags (ElfSection _ ElfSection32{..}) = ElfSectionFlag $ fromIntegral s32Flags

elfSectionAddr :: ElfSection -> Word64 -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
elfSectionAddr (ElfSection _ ElfSection64 {..}) = s64Addr
elfSectionAddr (ElfSection _ ElfSection32 {..}) = fromIntegral s32Addr

elfSectionSize :: ElfSection -> Word64 -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
elfSectionSize (ElfSection _ ElfSection64{..}) = s64Size
elfSectionSize (ElfSection _ ElfSection32{..}) = fromIntegral s32Size

elfSectionLink :: ElfSection -> Word32 -- ^ Contains a section index of an associated section, depending on section type.
elfSectionLink (ElfSection _ ElfSection64{..}) = s64Link
elfSectionLink (ElfSection _ ElfSection32{..}) = s32Link

elfSectionInfo :: ElfSection -> Word32 -- ^ Contains extra information for the index, depending on type.
elfSectionInfo (ElfSection _ ElfSection64 {..}) = s64Info
elfSectionInfo (ElfSection _ ElfSection32 {..}) = s32Info

elfSectionAddrAlign :: ElfSection -> Word64 -- ^ Contains the required alignment of the section. Must be a power of two.
elfSectionAddrAlign (ElfSection _ ElfSection64{..}) = s64AddrAlign
elfSectionAddrAlign (ElfSection _ ElfSection32{..}) = fromIntegral s32AddrAlign

elfSectionEntSize :: ElfSection -> Word64 -- ^ Size of entries if section has a table.
elfSectionEntSize (ElfSection _ ElfSection64{..}) = s64EntSize
elfSectionEntSize (ElfSection _ ElfSection32{..}) = fromIntegral s32EntSize

cut :: BS.ByteString -> Int -> Int -> BS.ByteString
cut content offset size = BS.take size $ BS.drop offset content

-- FIXME: this can fail on 32 bit machine working with 64 bit elfs
elfSectionData' :: ElfXX a -> ElfSectionXX a -> BS.ByteString
elfSectionData' ElfXX{..} ElfSection64{..} = cut exxContent (fromIntegral s64Offset) (fromIntegral s64Size)
elfSectionData' ElfXX{..} ElfSection32{..} = cut exxContent (fromIntegral s32Offset) (fromIntegral s32Size)

elfSectionData :: ElfSection -> BS.ByteString -- ^ The raw data for the section.
elfSectionData (ElfSection elfXX elfSectionXX) = elfSectionData' elfXX elfSectionXX

elfSectionInterval :: ElfSection -> I.Interval Word64
elfSectionInterval (ElfSection _ sXX) = if (t == SHT_NOBITS) || (s == 0) then I.empty else (o I.... o + s - 1)
    where
        (t, o, s) = case sXX of
            ElfSection32{..} -> (s32Type, fromIntegral s32Offset, fromIntegral s32Size)
            ElfSection64{..} -> (s64Type,              s64Offset,              s64Size)

elfSegmentInterval :: ElfSegment -> I.Interval Word64
elfSegmentInterval (ElfSegment _ pXX) = if (s == 0) then I.empty else (o I.... o + s - 1)
    where
        (o, s) = case pXX of
            ElfSegment32{..} -> (fromIntegral p32Offset, fromIntegral p32FileSize)
            ElfSegment64{..} -> (             p64Offset,              p64FileSize)

elfSegmentType :: ElfSegment -> ElfSegmentType -- ^ Segment type
elfSegmentType (ElfSegment _ ElfSegment64{..}) = p64Type
elfSegmentType (ElfSegment _ ElfSegment32{..}) = p32Type

elfSegmentFlags :: ElfSegment -> ElfSegmentFlag -- ^ Segment flags
elfSegmentFlags (ElfSegment _ ElfSegment64{..}) = ElfSegmentFlag p64Flags
elfSegmentFlags (ElfSegment _ ElfSegment32{..}) = ElfSegmentFlag p32Flags

elfSegmentVirtAddr :: ElfSegment -> Word64 -- ^ Virtual address for the segment
elfSegmentVirtAddr (ElfSegment _ ElfSegment64{..}) = p64VirtAddr
elfSegmentVirtAddr (ElfSegment _ ElfSegment32{..}) = fromIntegral p32VirtAddr

elfSegmentPhysAddr :: ElfSegment -> Word64 -- ^ Physical address for the segment
elfSegmentPhysAddr (ElfSegment _ ElfSegment64{..}) = p64PhysAddr
elfSegmentPhysAddr (ElfSegment _ ElfSegment32{..}) = fromIntegral p32PhysAddr

elfSegmentAlign :: ElfSegment -> Word64 -- ^ Segment alignment
elfSegmentAlign (ElfSegment _ ElfSegment64{..}) = p64Align
elfSegmentAlign (ElfSegment _ ElfSegment32{..}) = fromIntegral p32Align

elfSegmentData :: ElfSegment -> BS.ByteString -- ^ Data for the segment
elfSegmentData (ElfSegment ElfXX{..} ElfSegment64{..}) = cut exxContent (fromIntegral p64Offset) (fromIntegral p64FileSize)
elfSegmentData (ElfSegment ElfXX{..} ElfSegment32{..}) = cut exxContent (fromIntegral p32Offset) (fromIntegral p32FileSize)

elfSegmentMemSize :: ElfSegment -> Word64 -- ^ Size in memory  (may be larger then the segment's data)
elfSegmentMemSize (ElfSegment _ ElfSegment64{..}) = p64MemSize
elfSegmentMemSize (ElfSegment _ ElfSegment32{..}) = fromIntegral p32MemSize

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

getElf' :: forall (a :: ElfClass) . BS.ByteString -> Sing a -> Get Elf
getElf' exxContent exxClassS = do

    exxData     <- get

    let
        getE :: (Binary (Le b), Binary (Be b)) => Get b
        getE = getEndian exxData

    verify "version1" elfSupportedVersion
    exxOSABI      <- get
    exxABIVersion <- get
    skip 7
    exxType       <- getE
    exxMachine    <- getE

    (exxVersion2 :: Word32)  <- getE
    when (exxVersion2 /= 1) $ error "verification failed: version2"

    exxEntry      <- withSingI exxClassS $ getE

    exxPhOff      <- withSingI exxClassS $ getE
    exxShOff      <- withSingI exxClassS $ getE

    exxFlags      <- getE

    exxHSize      <- getE

    exxPhEntSize  <- getE
    exxPhNum      <- getE
    exxShEntSize  <- getE
    exxShNum      <- getE

    exxShStrNdx   <- getE

    hSize         <- bytesRead
    when (hSize /= fromIntegral exxHSize) $ error "incorrect size of elf header"

    exxSegments   <- withSingI exxClassS $ getTable exxData (fromWordXX exxPhOff - fromIntegral exxHSize) exxPhEntSize exxPhNum
    exxSections   <- withSingI exxClassS $ getTable exxData (fromWordXX exxShOff - fromIntegral exxHSize) exxShEntSize exxShNum

    return $ exxClassS :&: ElfXX{..}

getElf :: Get Elf
getElf = do

    eContent <- BSL.toStrict <$> lookAhead getRemainingLazyByteString

    verify "magic" elfMagic

    eClass    <- get

    withSomeSing eClass $ getElf' eContent

getElfSectionXX :: forall (c :: ElfClass) . Sing c -> (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get (ElfSectionXX c)
getElfSectionXX SELFCLASS64 getE = ElfSection64 <$> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
getElfSectionXX SELFCLASS32 getE = ElfSection32 <$> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE

getElfSegmentXX :: forall (c :: ElfClass) . Sing c -> (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get (ElfSegmentXX c)
getElfSegmentXX SELFCLASS64 getE = ElfSegment64 <$> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
getElfSegmentXX SELFCLASS32 getE = ElfSegment32 <$> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE
                                                <*> getE

splitBits :: (Num w, FiniteBits w) => w -> [w]
splitBits w = fmap (shiftL 1) $ L.filter (testBit w) $ fmap (subtract 1) [ 1 .. (finiteBitSize w) ]

data ElfSymbolTableEntryXX (c :: ElfClass) where
    ElfSymbolTableEntry64 ::
        { st64Name  :: Word32
        , st64Info  :: Word8
        , st64Other :: Word8
        , st64ShNdx :: Word16
        , st64Value :: Word64
        , st64Size  :: Word64
        } -> ElfSymbolTableEntryXX 'ELFCLASS64
    ElfSymbolTableEntry32 ::
        { st32Name  :: Word32
        , st32Value :: Word32
        , st32Size  :: Word32
        , st32Info  :: Word8
        , st32Other :: Word8
        , st32ShNdx :: Word16
        } -> ElfSymbolTableEntryXX 'ELFCLASS32

deriving instance Show (ElfSymbolTableEntryXX c)

getElfSymbolTableEntryXX :: Sing c -> (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get (ElfSymbolTableEntryXX c)
getElfSymbolTableEntryXX SELFCLASS64 getE = ElfSymbolTableEntry64 <$> getE -- Name
                                                                  <*> get  -- Info
                                                                  <*> get  -- Other
                                                                  <*> getE -- ShNdx
                                                                  <*> getE -- Value
                                                                  <*> getE -- Size
getElfSymbolTableEntryXX SELFCLASS32 getE = ElfSymbolTableEntry32 <$> getE -- Name
                                                                  <*> getE -- Value
                                                                  <*> getE -- Size
                                                                  <*> get  -- Info
                                                                  <*> get  -- Other
                                                                  <*> getE -- ShNdx

instance forall (c :: ElfClass) . SingI c => Binary (Le (ElfSymbolTableEntryXX c)) where
    put = undefined
    get = Le <$> getElfSymbolTableEntryXX sing (getEndian ELFDATA2LSB)

instance forall (c :: ElfClass) . SingI c => Binary (Be (ElfSymbolTableEntryXX c)) where
    put = undefined
    get = Be <$> getElfSymbolTableEntryXX sing (getEndian ELFDATA2LSB)

data ElfSymbolTableEntry = forall a . ElfSymbolTableEntry (ElfXX a) (ElfSectionXX a) (ElfSymbolTableEntryXX a)

steName :: ElfSymbolTableEntry -> Maybe BS.ByteString
steName (ElfSymbolTableEntry elfXX ElfSection64{..} ElfSymbolTableEntry64{..}) = getString elfXX s64Link st64Name
steName (ElfSymbolTableEntry elfXX ElfSection32{..} ElfSymbolTableEntry32{..}) = getString elfXX s32Link st32Name

steType :: ElfSymbolTableEntry -> ElfSymbolType
steType (ElfSymbolTableEntry _ _ ElfSymbolTableEntry64{..}) = ElfSymbolType (st64Info .&. 0x0F)
steType (ElfSymbolTableEntry _ _ ElfSymbolTableEntry32{..}) = ElfSymbolType (st32Info .&. 0x0F)

steBind :: ElfSymbolTableEntry -> ElfSymbolBinding
steBind (ElfSymbolTableEntry _ _ ElfSymbolTableEntry64{..}) = ElfSymbolBinding (st64Info `shiftR` 4)
steBind (ElfSymbolTableEntry _ _ ElfSymbolTableEntry32{..}) = ElfSymbolBinding (st32Info `shiftR` 4)

steIndex :: ElfSymbolTableEntry -> ElfSectionIndex
steIndex (ElfSymbolTableEntry _ _ ElfSymbolTableEntry64{..}) = ElfSectionIndex st64ShNdx
steIndex (ElfSymbolTableEntry _ _ ElfSymbolTableEntry32{..}) = ElfSectionIndex st32ShNdx

steValue :: ElfSymbolTableEntry -> Word64
steValue (ElfSymbolTableEntry _ _ ElfSymbolTableEntry64{..}) = st64Value
steValue (ElfSymbolTableEntry _ _ ElfSymbolTableEntry32{..}) = fromIntegral st32Value

steSize  :: ElfSymbolTableEntry -> Word64
steSize (ElfSymbolTableEntry _ _ ElfSymbolTableEntry64{..}) = st64Size
steSize (ElfSymbolTableEntry _ _ ElfSymbolTableEntry32{..}) = fromIntegral st32Size

steOther  :: ElfSymbolTableEntry -> Word8
steOther (ElfSymbolTableEntry _ _ ElfSymbolTableEntry64{..}) = st64Other
steOther (ElfSymbolTableEntry _ _ ElfSymbolTableEntry32{..}) = st32Other

instance Show ElfSymbolTableEntry where
    show (ElfSymbolTableEntry _ _ e) = show e

newtype BList a = BList { fromBList :: [a] }

instance Binary a => Binary (BList a) where
    put (BList (a:as)) = put a >> put as
    put (BList []) = return ()
    get = do
        e <- isEmpty
        if e then return $ BList [] else do
            a <- get
            (BList as) <- get
            return $ BList $ a : as

elfParseSymbolTableX :: forall (c :: ElfClass) . SingI c => ElfData -> BS.ByteString -> [ElfSymbolTableEntryXX c]
elfParseSymbolTableX d bs =
    let
        bsl = BSL.fromChunks [bs]
    in
        case d of
            ELFDATA2LSB -> fmap fromLe (fromBList (decode bsl))
            ELFDATA2MSB -> fmap fromBe (fromBList (decode bsl))

elfSectionXXToSing :: ElfSectionXX a -> Sing a
elfSectionXXToSing ElfSection64{..} = SELFCLASS64
elfSectionXXToSing ElfSection32{..} = SELFCLASS32

elfParseSymbolTable :: ElfSection -> [ElfSymbolTableEntry]
elfParseSymbolTable sec@(ElfSection elfXX@ElfXX{..} sXX) =
    if elfSectionType sec `L.elem` [SHT_SYMTAB, SHT_DYNSYM]
        then
            let
                s = elfSectionXXToSing sXX
                bs = elfSectionData' elfXX sXX
                stXX = withSingI s $ elfParseSymbolTableX exxData bs
            in
                ElfSymbolTableEntry elfXX sXX <$> stXX
        else []

--------------------------------------------------------------------------

type family WXX (a :: ElfClass) = r | r -> a where
-- type family WXX (a :: ElfClass) where
    WXX 'ELFCLASS64 = Word64
    WXX 'ELFCLASS32 = Word32

-- this is disgusting, but let's bear with it for a while
wxxS :: Sing a -> WXX a -> WordXX a
wxxS SELFCLASS64 w = W64 w
wxxS SELFCLASS32 w = W32 w

wxx :: SingI a => WXX a -> WordXX a
wxx w = wxxS sing w

wxxFromIntegralS :: Integral i => Sing a -> i -> WXX a
wxxFromIntegralS SELFCLASS64 = fromIntegral
wxxFromIntegralS SELFCLASS32 = fromIntegral

wxxFromIntegral :: (SingI a, Integral i) => i -> WXX a
wxxFromIntegral = wxxFromIntegralS sing

data SectionBuilder (c :: ElfClass) =
    SectionBuilder
        { sbStart  :: WXX c
        , sbLength :: WXX c
        , sbName   :: String
        , sbAddr   :: WXX c
        }

data SegmentBuilder (c :: ElfClass) =
    SegmentBuilder
        { pbStart  :: WXX c
        , pbLength :: WXX c
        , pbAddr   :: WXX c
        }

data ElfBuilderState (c :: ElfClass) =
    ElfBuilderState
        { _ebData        :: BSL.ByteString
        , _ebSectionsRev :: [SectionBuilder c]
        , _ebSegmentsRev :: [SegmentBuilder c]
        , _ebPhOff       :: Maybe (WXX c)
        , _ebShOff       :: Maybe (WXX c)
        }

makeLenses ''ElfBuilderState

stateInitial :: SingI a => ElfBuilderState a
stateInitial = ElfBuilderState BSL.empty [] [] Nothing Nothing

type ElfBuilderT a = StateT (ElfBuilderState a)

-- data ElfSectionXX (c :: ElfClass) where
--     ElfSection64 ::
--         { s64Name      :: Word32
--         , s64Type      :: ElfSectionType    -- ^ Identifies the type of the section.
--         , s64Flags     :: Word64            -- ^ Identifies the attributes of the section.
--         , s64Addr      :: Word64            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
--         , s64Offset    :: Word64
--         , s64Size      :: Word64            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
--         , s64Link      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
--         , s64Info      :: Word32            -- ^ Contains extra information for the index, depending on type.
--         , s64AddrAlign :: Word64            -- ^ Contains the required alignment of the section. Must be a power of two.
--         , s64EntSize   :: Word64            -- ^ Size of entries if section has a table.
--         } -> ElfSectionXX 'ELFCLASS64
--     ElfSection32 ::
--         { s32Name      :: Word32
--         , s32Type      :: ElfSectionType    -- ^ Identifies the type of the section.
--         , s32Flags     :: Word32            -- ^ Identifies the attributes of the section.
--         , s32Addr      :: Word32            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
--         , s32Offset    :: Word32
--         , s32Size      :: Word32            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
--         , s32Link      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
--         , s32Info      :: Word32            -- ^ Contains extra information for the index, depending on type.
--         , s32AddrAlign :: Word32            -- ^ Contains the required alignment of the section. Must be a power of two.
--         , s32EntSize   :: Word32            -- ^ Size of entries if section has a table.
--         } -> ElfSectionXX 'ELFCLASS32

dataLength :: (Monad m, SingI a) => ElfBuilderT a m (WXX a)
dataLength = (wxxFromIntegral . BSL.length) <$> use ebData

mkSection :: (Monad m, SingI a) => String -> WXX a -> BSL.ByteString -> ElfBuilderT a m ()
mkSection name address d = do
    l <- dataLength
    ebData %= (flip BSL.append $ d)
    let
        s = SectionBuilder l (wxxFromIntegral $ BSL.length d) name address
    ebSectionsRev %= (s :)

mkSegment :: (Monad m, SingI a) => ElfBuilderT a m () -> ElfBuilderT a m ()
mkSegment = id

mkHeader :: (Monad m, SingI a) => ElfBuilderT a m ()
mkHeader = undefined

mkSectionTable :: (Monad m, SingI a) => ElfBuilderT a m ()
mkSectionTable =  do
    l <- dataLength
    ebShOff .= Just l

mkSegmentTable :: (Monad m, SingI a) => ElfBuilderT a m ()
mkSegmentTable =  do
    l <- dataLength
    ebPhOff .= Just l

{-
data ElfXX (c :: ElfClass) =
    ElfXX
        { exxData       :: ElfData    -- ^ Identifies the data encoding of the object file (endianness).
        , exxOSABI      :: ElfOSABI   -- ^ Identifies the operating system and ABI for which the object is prepared.
        , exxABIVersion :: Word8      -- ^ Identifies the ABI version for which the object is prepared.
        , exxType       :: ElfType    -- ^ Identifies the object file type.
        , exxMachine    :: ElfMachine -- ^ Identifies the target architecture.
        , exxEntry      :: WordXX c

        , exxPhOff      :: WordXX c   -- contains the file offset, in bytes, of the program header table.
        , exxShOff      :: WordXX c   -- contains the file offset, in bytes, of the section header table.

        , exxFlags      :: Word32

        , exxHSize      :: Word16     -- contains the size, in bytes, of the ELF header.

        , exxPhEntSize  :: Word16     -- contains the size, in bytes, of a program header table entry
        , exxPhNum      :: Word16     -- contains the number of entries in the program header table
        , exxShEntSize  :: Word16     -- contains the size, in bytes, of a program header table entry
        , exxShNum      :: Word16     -- contains the number of entries in the section header table

        , exxShStrNdx   :: ElfSectionIndex -- contains the section header table index of the section
                                           -- containing the section name string table. If there is no section name string
                                           -- table, this field has the value SHN_UNDEF (0)

        , exxSegments   :: [ElfSegmentXX c]
        , exxSections   :: [ElfSectionXX c]
        , exxContent    :: BS.ByteString

        }
-}

-- mkElf :: (Monad m, SingI a) => ElfData -> ElfOSABI -> Word8 -> ElfType -> ElfMachine -> WXX a -> ElfBuilderT a m () -> m Elf
mkElf :: Monad m => Sing a -> ElfData -> ElfOSABI -> Word8 -> ElfType -> ElfMachine -> WXX a -> ElfBuilderT a m () -> m Elf
mkElf exxClassS exxData exxOSABI exxABIVersion exxType exxMachine exxEntry' b = do

    ElfBuilderState{..} <- execStateT b $ withSingI exxClassS stateInitial

    let
        exxEntry = wxxS exxClassS exxEntry'
        exxShStrNdx = SHN_Undef
        exxSegments = []
        exxSections = []

        exxContent = toStrict _ebData

        exxPhOff = withSingI exxClassS $ wxx $ wxxFromIntegral (0 :: Integer)
        exxShOff = withSingI exxClassS $ wxx $ wxxFromIntegral (0 :: Integer)

        exxFlags = 0

        exxHSize = 0

        exxPhEntSize = 0
        exxPhNum = 0
        exxShEntSize = 0
        exxShNum = 0

    return $ exxClassS :&: ElfXX{..}
