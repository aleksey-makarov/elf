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
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Data.Elf is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf ( ElfClass(..)
                , ElfData(..)

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
                , steNameIndex
                , steName
                , steType
                , steBind
                , steIndex
                , steValue
                , steSize
                , elfParseSymbolTable

{-
                , findSymbolDefinition
                , findSectionByName
-}
                , module Data.Elf.Generated) where


import Data.Binary
import Data.Binary.Get as G
import Data.Bits
import Data.Kind
import Control.Monad
import qualified Data.ByteString       as B
import qualified Data.ByteString.Lazy  as L
import qualified Data.ByteString.Char8 as C
import Data.Singletons.TH
import Data.Singletons.Sigma

-- https://stackoverflow.com/questions/10672981/export-template-haskell-generated-definitions

import Data.Elf.Generated

$(singletons [d|
    data ElfClass
        = ELFCLASS32 -- ^ 32-bit ELF format
        | ELFCLASS64 -- ^ 64-bit ELF format
        deriving (Eq, Show)

    -- type MyTypeFamily (b :: Bool) :: Type where
    --     MyTypeFamily 'False = Int
    --     MyTypeFamily 'True  = String

    -- type family WordXX (a :: ElfClass) :: Type where
    --     WordXX 'ELFCLASS32 = Word32
    --     WordXX 'ELFCLASS64 = Word64

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

-- Can I get rid of this SingI???
instance forall (a :: ElfClass) . SingI a => Binary (Be (ElfSectionXX a)) where
-- instance forall (a :: ElfClass) . Binary (Be (ElfSectionXX a)) where
    put = undefined
    get = Be <$> getElfSectionXX sing (getEndian ELFDATA2MSB)

instance forall (a :: ElfClass) . SingI a => Binary (Le (ElfSectionXX a)) where
-- instance forall (a :: ElfClass) . Binary (Le (ElfSectionXX a)) where
    put = undefined
    get = Le <$> getElfSectionXX sing (getEndian ELFDATA2LSB)

-- instance Binary (Be (ElfSectionXX 'ELFCLASS32)) where
--     put = undefined
--     get = Be <$> getElfSection32 (getEndian ELFDATA2MSB)
--
-- instance Binary (Le (ElfSectionXX 'ELFCLASS32)) where
--     put = undefined
--     get = Le <$> getElfSection32 (getEndian ELFDATA2LSB)

data ElfSection = forall a . ElfSection (ElfXX a) (ElfSectionXX a)

data ElfSegmentXX (c :: ElfClass) where
    ElfSegment64 ::
        { p64Type     :: ElfSegmentType   -- ^ Segment type
        , p64Flags    :: Word32           -- ^ Segment flags
        , p64Offset   :: Word64
        , p64VirtAddr :: Word64           -- ^ Virtual address for the segment
        , p64PhysAddr :: Word64           -- ^ Physical address for the segment
        , p64PileSize :: Word64
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

--instance Binary (Be (ElfSegmentXX 'ELFCLASS64)) where
--    put = undefined
--    get = Be <$> getElfSegment64 (getEndian ELFDATA2MSB)
--
--instance Binary (Le (ElfSegmentXX 'ELFCLASS64)) where
--    put = undefined
--    get = Le <$> getElfSegment64 (getEndian ELFDATA2LSB)
--
--instance Binary (Be (ElfSegmentXX 'ELFCLASS32)) where
--    put = undefined
--    get = Be <$> getElfSegment32 (getEndian ELFDATA2MSB)
--
--instance Binary (Le (ElfSegmentXX 'ELFCLASS32)) where
--    put = undefined
--    get = Le <$> getElfSegment32 (getEndian ELFDATA2LSB)

data ElfSegment = forall a . ElfSegment (ElfXX a) (ElfSegmentXX a)

-- FIXME: No, this is not good.  Use Sigma or/and type synonym
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

-- data ElfXX (c :: ElfClass) where
--     Elf64 ::
--         { e64Entry    :: Word64
--         , e64Segments :: [ElfSegmentXX c]
--         , e64Sections :: [ElfSectionXX c]
--         } -> ElfXX 'ELFCLASS64
--     Elf32 ::
--         { e32Entry    :: Word32
--         , e32Segments :: [ElfSegmentXX c]
--         , e32Sections :: [ElfSectionXX c]
--         } -> ElfXX 'ELFCLASS32

--data ElfCommon =
--    ElfCommon

data ElfXX (c :: ElfClass) =
    ElfXX
        { exxData       :: ElfData       -- ^ Identifies the data encoding of the object file (endianness).
        , exxOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
        , exxABIVersion :: Word8         -- ^ Identifies the ABI version for which the object is prepared.
        , exxType       :: ElfType       -- ^ Identifies the object file type.
        , exxMachine    :: ElfMachine    -- ^ Identifies the target architecture.
        , exxEntry      :: WordXX c
        , exxFlags      :: Word32
        , exxShStrNdx   :: Word16
        , exxSegments   :: [ElfSegmentXX c]
        , exxSections   :: [ElfSectionXX c]
        , exxContent    :: B.ByteString
        }

-- data Elf = forall a . Elf (ElfXX a)

type Elf = Sigma ElfClass (TyCon1 ElfXX)

instance Binary Elf where
    put = undefined
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

at :: (Integral i) => [a] -> i -> Maybe a
at (x : _)  0             = Just x
at (_ : xs) n | n > 0     = xs `at` (n - 1)
              | otherwise = Nothing
at _        _             = Nothing

nameToString :: Maybe B.ByteString -> String
nameToString bs = maybe "" id $ C.unpack <$> bs

getStringSectionData :: ElfXX a -> Word32 -> Maybe B.ByteString
getStringSectionData elfXX@ElfXX{..} sectionIndex = elfSectionData' elfXX <$> exxSections `at` sectionIndex

getString :: ElfXX a -> Word32 -> Word32 -> Maybe B.ByteString
getString elfXX sectionIndex offset = B.takeWhile (/= 0) <$> B.drop (fromIntegral offset) <$> getStringSectionData elfXX sectionIndex

-- FIXME: export the index of the string, not the name
elfSectionName :: ElfSection -> Maybe B.ByteString -- ^ Identifies the name of the section.
elfSectionName (ElfSection elfXX@ElfXX{..} ElfSection64{..}) = getString elfXX (fromIntegral exxShStrNdx) s64Name
elfSectionName (ElfSection elfXX@ElfXX{..} ElfSection32{..}) = getString elfXX (fromIntegral exxShStrNdx) s32Name

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

cut :: B.ByteString -> Int -> Int -> B.ByteString
cut content offset size = B.take size $ B.drop offset content

-- FIXME: this can fail on 32 bit machine working with 64 bit elfs
elfSectionData' :: ElfXX a -> ElfSectionXX a -> B.ByteString
elfSectionData' ElfXX{..} ElfSection64{..} = cut exxContent (fromIntegral s64Offset) (fromIntegral s64Size)
elfSectionData' ElfXX{..} ElfSection32{..} = cut exxContent (fromIntegral s32Offset) (fromIntegral s32Size)

elfSectionData :: ElfSection -> B.ByteString -- ^ The raw data for the section.
elfSectionData (ElfSection elfXX elfSectionXX) = elfSectionData' elfXX elfSectionXX

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

elfSegmentData :: ElfSegment -> B.ByteString -- ^ Data for the segment
elfSegmentData (ElfSegment ElfXX{..} ElfSegment64{..}) = cut exxContent (fromIntegral p64Offset) (fromIntegral p64PileSize)
elfSegmentData (ElfSegment ElfXX{..} ElfSegment32{..}) = cut exxContent (fromIntegral p32Offset) (fromIntegral p32FileSize)

elfSegmentMemSize :: ElfSegment -> Word64 -- ^ Size in memory  (may be larger then the segment's data)
elfSegmentMemSize (ElfSegment _ ElfSegment64{..}) = p64MemSize
elfSegmentMemSize (ElfSegment _ ElfSegment32{..}) = fromIntegral p32MemSize

elfMagic :: Word32
elfMagic = 0x7f454c46 -- "\DELELF"

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

{-
getXX :: forall proxy b w . (Integral w,
                             Num b,
                             Binary (Le w), Binary (Be w))
         => proxy w
         -> ElfData
         -> Get b
getXX _ e_data = (fromIntegral :: w -> b) <$> getEndian e_data
-}

-- getXX :: forall a b . (Integral a, Num b, Binary (Le a), Binary (Be a) ) => Sing a -> ElfData -> Get b
-- getXX _ eData = (fromIntegral :: a -> b) <$> getEndian eData

-- type family WordXX (a :: ElfClass) :: Type where
--     WordXX 'ELFCLASS32 = Word32
--     WordXX 'ELFCLASS64 = Word64

--instance (b ~ WordXX a) => Num b where
--    (+) = undefined
--    (*) = undefined
--    abs = undefined
--    signum = undefined
--    fromInteger = undefined
--    negate = undefined

-- mkElfXX :: Sing a -> {- WordXX a -> -} [ElfSegmentXX a] -> [ElfSectionXX a] -> ElfXX a
-- mkElfXX :: forall (a :: ElfClass) . Sigma ElfClass WordXXSym0 -> [ElfSegmentXX a] -> [ElfSectionXX a] -> ElfXX a
-- mkElfXX = undefined

{-
getElf' :: forall c w . (ElfXXTools c w,
                         Integral w,
                         Binary (Le w), Binary (Be w),
                         Binary (Le (ElfSegmentXX c)), Binary (Be (ElfSegmentXX c)),
                         Binary (Le (ElfSectionXX c)), Binary (Be (ElfSectionXX c)))
        => Proxy (c :: ElfClass)
        -> B.ByteString
        -> ElfData
        -> Get Elf
-}

-- getElf' :: forall (a :: ElfClass) . (Binary (Le (WordXX a)), Binary (Be (WordXX a)), SingI a) => B.ByteString -> ElfData -> Sing a -> Get Elf
-- getElf' :: forall (a :: ElfClass) . SingI a => B.ByteString -> ElfData -> Sing a -> Get Elf
getElf' :: forall (a :: ElfClass) . B.ByteString -> Sing a -> Get Elf
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

    (exxPhOff :: WordXX a) <- withSingI exxClassS $ getE
    (exxShOff :: WordXX a) <- withSingI exxClassS $ getE

    exxFlags      <- getE

    (exxEhSize :: Word16) <- getE

    (exxPhEntSize :: Word16)  <- getE
    (exxPhNum     :: Word16)  <- getE
    (exxShEntSize :: Word16)  <- getE
    (exxShNum     :: Word16)  <- getE

    exxShStrNdx   <- getE

    hSize         <- bytesRead
    when (hSize /= fromIntegral exxEhSize) $ error "incorrect size of elf header"

    exxSegments   <- withSingI exxClassS $ getTable exxData (fromWordXX exxPhOff - fromIntegral exxEhSize) exxPhEntSize exxPhNum
    exxSections   <- withSingI exxClassS $ getTable exxData (fromWordXX exxShOff - fromIntegral exxEhSize) exxShEntSize exxShNum

    return $ exxClassS :&: ElfXX{..}

getElf :: Get Elf
getElf = do

    eContent <- L.toStrict <$> lookAhead getRemainingLazyByteString

    -- FIXME: it does not specify endianness!
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
splitBits w = map (shiftL 1) $ filter (testBit w) $ map (subtract 1) [ 1 .. (finiteBitSize w) ]

-- data ElfReader = ElfReader
--     { getWord16 :: Get Word16
--     , getWord32 :: Get Word32
--     , getWord64 :: Get Word64
--     }

-- elfReader :: ElfData -> ElfReader
-- elfReader ELFDATA2LSB = ElfReader { getWord16 = getWord16le, getWord32 = getWord32le, getWord64 = getWord64le }
-- elfReader ELFDATA2MSB = ElfReader { getWord16 = getWord16be, getWord32 = getWord32be, getWord64 = getWord64be }

-- -- | The symbol table entries consist of index information to be read from other
-- -- parts of the ELF file. Some of this information is automatically retrieved
-- -- for your convenience (including symbol name, description of the enclosing
-- -- section, and definition).
-- data ElfSymbolTableEntry = EST
--     { steName             :: (Word32,Maybe B.ByteString)
-- --    , steEnclosingSection :: Maybe ElfSection -- ^ Section from steIndex
--     , steType             :: ElfSymbolType
--     , steBind             :: ElfSymbolBinding
--     , steOther            :: Word8
--     , steIndex            :: ElfSectionIndex  -- ^ Section in which the def is held
--     , steValue            :: Word64
--     , steSize             :: Word64
--     } deriving (Eq, Show)

data ElfSymbolTableEntryXX (c :: ElfClass) where
    ElfSymbolTableEntry64 ::
        { st64Name  :: Word32
        , st64Info  :: Word8
        -- , st64Other :: Word8 -- FIXME: there was non-zero entries in bloated
        , st64ShNdx :: Word16
        , st64Value :: Word64
        , st64Size  :: Word64
        } -> ElfSymbolTableEntryXX 'ELFCLASS64
    ElfSymbolTableEntry32 ::
        { st32Name  :: Word32
        , st32Value :: Word32
        , st32Size  :: Word32
        , st32Info  :: Word8
        -- , st32Other :: Word8 -- FIXME
        , st32ShNdx :: Word16
        } -> ElfSymbolTableEntryXX 'ELFCLASS32

-- instance Binary (Be (ElfSymbolTableEntryXX 'ELFCLASS64)) where
--     put = undefined
--     get = Be <$> getElfSymbolTableEntry64 (getEndian ELFDATA2MSB)
--
-- instance Binary (Le (ElfSymbolTableEntryXX 'ELFCLASS64)) where
--     put = undefined
--     get = Le <$> getElfSymbolTableEntry64 (getEndian ELFDATA2LSB)
--
-- instance Binary (Be (ElfSymbolTableEntryXX 'ELFCLASS32)) where
--     put = undefined
--     get = Be <$> getElfSymbolTableEntry32 (getEndian ELFDATA2MSB)
--
-- instance Binary (Le (ElfSymbolTableEntryXX 'ELFCLASS32)) where
--     put = undefined
--     get = Le <$> getElfSymbolTableEntry32 (getEndian ELFDATA2LSB)

getElfSymbolTableEntryXX :: Sing c -> (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get (ElfSymbolTableEntryXX c)
getElfSymbolTableEntryXX SELFCLASS64 getE = ElfSymbolTableEntry64 <$> getE              -- Name
                                                                  <*> (get <* getWord8) -- Info, Other
                                                                  <*> getE              -- ShNdx
                                                                  <*> getE              -- Value
                                                                  <*> getE              -- Size
getElfSymbolTableEntryXX SELFCLASS32 getE = ElfSymbolTableEntry32 <$> getE              -- Name
                                                                  <*> getE              -- Value
                                                                  <*> getE              -- Size
                                                                  <*> (get <* getWord8) -- Info, Other
                                                                  <*> getE              -- ShNdx

instance forall (c :: ElfClass) . SingI c => Binary (Le (ElfSymbolTableEntryXX c)) where
    put = undefined
    get = Le <$> getElfSymbolTableEntryXX sing (getEndian ELFDATA2LSB)

instance forall (c :: ElfClass) . SingI c => Binary (Be (ElfSymbolTableEntryXX c)) where
    put = undefined
    get = Be <$> getElfSymbolTableEntryXX sing (getEndian ELFDATA2LSB)

data ElfSymbolTableEntry = forall a . ElfSymbolTableEntry (ElfXX a) (ElfSectionXX a) (ElfSymbolTableEntryXX a)

steNameIndex :: ElfSymbolTableEntry -> Word32
steNameIndex (ElfSymbolTableEntry _ _ ElfSymbolTableEntry64{..}) = st64Name
steNameIndex (ElfSymbolTableEntry _ _ ElfSymbolTableEntry32{..}) = st32Name

steName :: ElfSymbolTableEntry -> Maybe B.ByteString
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

instance Show ElfSymbolTableEntry where
    show (ElfSymbolTableEntry _ _ ElfSymbolTableEntry64 {..}) =
        "ElfSymbolTableEntry64 { name: "  ++ show st64Name  ++
                              ", info: "  ++ show st64Info  ++
                              ", shNdx: " ++ show st64ShNdx ++
                              ", value: " ++ show st64Value ++
                              ", size: "  ++ show st64Size  ++ " }"
    show (ElfSymbolTableEntry _ _ ElfSymbolTableEntry32 {..}) =
        "ElfSymbolTableEntry64 { name: "  ++ show st32Name  ++
                              ", info: "  ++ show st32Info  ++
                              ", shNdx: " ++ show st32ShNdx ++
                              ", value: " ++ show st32Value ++
                              ", size: "  ++ show st32Size  ++ " }"

-- -- | Assumes the given section is a symbol table, type SHT_SYMTAB, or SHT_DYNSYM
-- -- (guaranteed by parseSymbolTables).
-- getSymbolTableEntries :: Elf -> ElfSection -> [ElfSymbolTableEntry]
-- getSymbolTableEntries e s = go decoder (L.fromChunks [elfSectionData s])
--   where
--     link   = elfSectionLink s
--     strtab = lookup link (zip [0..] (elfSections e))
--     decoder = runGetIncremental (getSymbolTableEntry e strtab)
--     go :: Decoder ElfSymbolTableEntry -> L.ByteString -> [ElfSymbolTableEntry]
--     go (Done leftover _ entry) input =
--       entry : go decoder (L.Chunk leftover input)
--     go (Partial k) input =
--       go (k . takeHeadChunk $ input) (dropHeadChunk input)
--     go (Fail _ _ msg) input = if L.null input
--                               then []
--                               else error msg

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

elfParseSymbolTableX :: forall (c :: ElfClass) . SingI c => ElfData -> B.ByteString -> [ElfSymbolTableEntryXX c]
elfParseSymbolTableX d bs =
    let
        bsl = L.fromChunks [bs]
    in
        case d of
            ELFDATA2LSB -> fmap fromLe (fromBList (decode bsl))
            ELFDATA2MSB -> fmap fromBe (fromBList (decode bsl))

elfSectionXXToSing :: ElfSectionXX a -> Sing a
elfSectionXXToSing ElfSection64{..} = SELFCLASS64
elfSectionXXToSing ElfSection32{..} = SELFCLASS32

elfParseSymbolTable :: ElfSection -> [ElfSymbolTableEntry]
elfParseSymbolTable sec@(ElfSection elfXX@ElfXX{..} sXX) =
    if elfSectionType sec `elem` [SHT_SYMTAB, SHT_DYNSYM]
        then
            let
                s = elfSectionXXToSing sXX
                bs = elfSectionData' elfXX sXX
                stXX = withSingI s $ elfParseSymbolTableX exxData bs
            in
                ElfSymbolTableEntry elfXX sXX <$> stXX
        else []


-- elfParseSymbolTable :: ElfSection -> [ElfSymbolTableEntry]
-- elfParseSymbolTable = undefined
-- elfParseSymbolTable s@(ElfSection (Elf {..}) _) = undefined

    -- Elf64 {} -> ElfSymbolTableEntry s <$> (getList (getElfSymbolTableEntry64 $ getEndian elfData) (elfSectionData s))
    -- Elf32 {} -> ElfSymbolTableEntry s <$> (fromBList (decode (L.fromChunks [elfSectionData s])))

    -- Elf32 {} -> ElfSymbolTableEntry s <$> undefined
--    Elf32 {} -> undefined
    --    where

-- elfParseSymbolTable :: ElfSection -> [ElfSymbolTableEntry]
-- elfParseSymbolTable s@(ElfSection elfXX sXX) =
--     if elfSectionType s `elem` [SHT_SYMTAB, SHT_DYNSYM]
--         then getSymbolTableEntries elfXX sXX
--         else []

-- takeHeadChunk :: L.ByteString -> Maybe B.ByteString
-- takeHeadChunk lbs =
--   case lbs of
--     (L.Chunk bs _) -> Just bs
--     _ -> Nothing

-- dropHeadChunk :: L.ByteString -> L.ByteString
-- dropHeadChunk lbs =
--   case lbs of
--     (L.Chunk _ lbs') -> lbs'
--     _ -> L.Empty

-- | Use the symbol offset and size to extract its definition
-- (in the form of a ByteString).
-- If the size is zero, or the offset larger than the 'elfSectionData',
-- then 'Nothing' is returned.
-- findSymbolDefinition :: ElfSymbolTableEntry -> Maybe B.ByteString
-- findSymbolDefinition e = steEnclosingSection e >>= \enclosingSection ->
--     let enclosingData = elfSectionData enclosingSection
--         start = (fromIntegral (steValue e)) - (fromIntegral (elfSectionAddr enclosingSection))
--         len = fromIntegral (steSize e)
--         def = (B.take len . B.drop start) enclosingData
--     in if B.null def then Nothing else Just def

-- -- | Gets a single entry from the symbol table, use with runGetMany.
-- getSymbolTableEntry :: Elf -> Maybe ElfSection -> Get ElfSymbolTableEntry
-- getSymbolTableEntry e strtlb =
--     if elfClass e == ELFCLASS32 then getSymbolTableEntry32 else getSymbolTableEntry64
--   where
--   strs = maybe B.empty elfSectionData strtlb
--   er = elfReader (elfData e)
--   getSymbolTableEntry32 = do
--     nameIdx <- liftM fromIntegral (getWord32 er)
--     value <- liftM fromIntegral (getWord32 er)
--     size  <- liftM fromIntegral (getWord32 er)
--     info  <- getWord8
--     other <- getWord8
--     sTlbIdx <- liftM (ElfSectionIndex . fromIntegral) (getWord16 er)
--     let name = stringByIndex nameIdx strs
--         (typ,bind) = infoToTypeAndBind info
--         -- sec = sectionByIndex e sTlbIdx
--     return $ EST (nameIdx,name) typ bind other sTlbIdx value size
--   getSymbolTableEntry64 = do
--     nameIdx <- liftM fromIntegral (getWord32 er)
--     info <- getWord8
--     other <- getWord8
--     sTlbIdx <- liftM (ElfSectionIndex . fromIntegral) (getWord16 er)
--     symVal <- getWord64 er
--     size <- getWord64 er
--     let name = stringByIndex nameIdx strs
--         (typ,bind) = infoToTypeAndBind info
--         -- sec = sectionByIndex e sTlbIdx
--     return $ EST (nameIdx,name) typ bind other sTlbIdx symVal size

-- -- | Given a section name, extract the ElfSection.
-- findSectionByName :: String -> Elf -> Maybe ElfSection
-- findSectionByName name = listToMaybe . filter ((==) name . elfSectionName) . elfSections

-- -- Get a string from a strtab ByteString.
-- stringByIndex :: Integral n => n -> B.ByteString -> Maybe B.ByteString
-- stringByIndex n strtab =
--     let str = (B.takeWhile (/=0) . B.drop (fromIntegral n)) strtab
--     in if B.length str == 0 then Nothing else Just str
