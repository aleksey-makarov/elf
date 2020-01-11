{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GADTSyntax #-}

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

                , parseElf
                , splitBits

                , ElfSymbolTableEntry(..)
                , ElfSymbolType(..)
                , ElfSymbolBinding(..)
                , ElfSectionIndex(..)
                , parseSymbolTables
{-
                  parseSymbolTables
                , findSymbolDefinition
                , findSectionByName

-}
                , module Data.Elf.Generated) where

import Data.Binary
import Data.Binary.Get as G
import Data.Bits
import Data.Maybe
import Control.Monad
import qualified Data.ByteString               as B
import qualified Data.ByteString.Lazy          as L
import qualified Data.ByteString.Lazy.Internal as L
import qualified Data.ByteString.Char8         as C
import Data.Proxy

-- https://stackoverflow.com/questions/10672981/export-template-haskell-generated-definitions
import Data.Elf.Generated

-- data Elf = Elf
--     { elfClass      :: ElfClass      -- ^ Identifies the class of the object file (32/64 bit).
--     , elfData       :: ElfData       -- ^ Identifies the data encoding of the object file (endianness).
--     , elfOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
--     , elfABIVersion :: Word8         -- ^ Identifies the ABI version for which the object is prepared.
--     , elfType       :: ElfType       -- ^ Identifies the object file type.
--     , elfMachine    :: ElfMachine    -- ^ Identifies the target architecture.
--     , elfEntry      :: Word64        -- ^ Virtual address of the program entry point. 0 for non-executable Elfs.
--     , elfSections   :: [ElfSection]  -- ^ List of sections in the file.
--     , elfSegments   :: [ElfSegment]  -- ^ List of segments in the file.
--     } deriving (Eq, Show)

-- data ElfSection = ElfSection
--     { elfSectionName      :: String            -- ^ Identifies the name of the section.
--     , elfSectionType      :: ElfSectionType    -- ^ Identifies the type of the section.
--     , elfSectionFlags     :: Word64            -- ^ Identifies the attributes of the section.
--     , elfSectionAddr      :: Word64            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
--     , elfSectionSize      :: Word64            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
--     , elfSectionLink      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
--     , elfSectionInfo      :: Word32            -- ^ Contains extra information for the index, depending on type.
--     , elfSectionAddrAlign :: Word64            -- ^ Contains the required alignment of the section. Must be a power of two.
--     , elfSectionEntSize   :: Word64            -- ^ Size of entries if section has a table.
--     , elfSectionData      :: B.ByteString      -- ^ The raw data for the section.
--     } deriving (Eq, Show)

-- data ElfSegment = ElfSegment
--   { elfSegmentType      :: ElfSegmentType   -- ^ Segment type
--   , elfSegmentFlags     :: Word32           -- ^ Segment flags
--   , elfSegmentVirtAddr  :: Word64           -- ^ Virtual address for the segment
--   , elfSegmentPhysAddr  :: Word64           -- ^ Physical address for the segment
--   , elfSegmentAlign     :: Word64           -- ^ Segment alignment
--   , elfSegmentData      :: B.ByteString     -- ^ Data for the segment
--   , elfSegmentMemSize   :: Word64           -- ^ Size in memory  (may be larger then the segment's data)
--   } deriving (Eq,Show)

data ElfClass
    = ELFCLASS32 -- ^ 32-bit ELF format
    | ELFCLASS64 -- ^ 64-bit ELF format
    deriving (Eq, Show)

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
        { elf64SectionName      :: Word32
        , elf64SectionType      :: ElfSectionType    -- ^ Identifies the type of the section.
        , elf64SectionFlags     :: Word64            -- ^ Identifies the attributes of the section.
        , elf64SectionAddr      :: Word64            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
        , elf64SectionOffset    :: Word64
        , elf64SectionSize      :: Word64            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
        , elf64SectionLink      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
        , elf64SectionInfo      :: Word32            -- ^ Contains extra information for the index, depending on type.
        , elf64SectionAddrAlign :: Word64            -- ^ Contains the required alignment of the section. Must be a power of two.
        , elf64SectionEntSize   :: Word64            -- ^ Size of entries if section has a table.
        } -> ElfSectionXX 'ELFCLASS64
    ElfSection32 ::
        { elf32SectionName      :: Word32
        , elf32SectionType      :: ElfSectionType    -- ^ Identifies the type of the section.
        , elf32SectionFlags     :: Word32            -- ^ Identifies the attributes of the section.
        , elf32SectionAddr      :: Word32            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
        , elf32SectionOffset    :: Word32
        , elf32SectionSize      :: Word32            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
        , elf32SectionLink      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
        , elf32SectionInfo      :: Word32            -- ^ Contains extra information for the index, depending on type.
        , elf32SectionAddrAlign :: Word32            -- ^ Contains the required alignment of the section. Must be a power of two.
        , elf32SectionEntSize   :: Word32            -- ^ Size of entries if section has a table.
        } -> ElfSectionXX 'ELFCLASS32

instance Binary (Be (ElfSectionXX 'ELFCLASS64)) where
    put = undefined
    get = Be <$> getElfSection64 (getEndian ELFDATA2MSB)

instance Binary (Le (ElfSectionXX 'ELFCLASS64)) where
    put = undefined
    get = Le <$> getElfSection64 (getEndian ELFDATA2LSB)

instance Binary (Be (ElfSectionXX 'ELFCLASS32)) where
    put = undefined
    get = Be <$> getElfSection32 (getEndian ELFDATA2MSB)

instance Binary (Le (ElfSectionXX 'ELFCLASS32)) where
    put = undefined
    get = Le <$> getElfSection32 (getEndian ELFDATA2LSB)

data ElfSection = forall a . ElfSection Elf (ElfSectionXX a)

data ElfSegmentXX (c :: ElfClass) where
    ElfSegment64 ::
        { elf64SegmentType     :: ElfSegmentType   -- ^ Segment type
        , elf64SegmentFlags    :: Word32           -- ^ Segment flags
        , elf64SegmentOffset   :: Word64
        , elf64SegmentVirtAddr :: Word64           -- ^ Virtual address for the segment
        , elf64SegmentPhysAddr :: Word64           -- ^ Physical address for the segment
        , elf64SegmentFileSize :: Word64
        , elf64SegmentMemSize  :: Word64           -- ^ Size in memory  (may be larger then the segment's data)
        , elf64SegmentAlign    :: Word64           -- ^ Segment alignment
        } -> ElfSegmentXX 'ELFCLASS64
    ElfSegment32 ::
        { elf32SegmentType     :: ElfSegmentType   -- ^ Segment type
        , elf32SegmentOffset   :: Word32
        , elf32SegmentVirtAddr :: Word32           -- ^ Virtual address for the segment
        , elf32SegmentPhysAddr :: Word32           -- ^ Physical address for the segment
        , elf32SegmentFileSize :: Word32
        , elf32SegmentMemSize  :: Word32           -- ^ Size in memory  (may be larger then the segment's data)
        , elf32SegmentFlags    :: Word32           -- ^ Segment flags
        , elf32SegmentAlign    :: Word32           -- ^ Segment alignment
        } -> ElfSegmentXX 'ELFCLASS32

instance Binary (Be (ElfSegmentXX 'ELFCLASS64)) where
    put = undefined
    get = Be <$> getElfSegment64 (getEndian ELFDATA2MSB)

instance Binary (Le (ElfSegmentXX 'ELFCLASS64)) where
    put = undefined
    get = Le <$> getElfSegment64 (getEndian ELFDATA2LSB)

instance Binary (Be (ElfSegmentXX 'ELFCLASS32)) where
    put = undefined
    get = Be <$> getElfSegment32 (getEndian ELFDATA2MSB)

instance Binary (Le (ElfSegmentXX 'ELFCLASS32)) where
    put = undefined
    get = Le <$> getElfSegment32 (getEndian ELFDATA2LSB)

data ElfSegment = forall a . ElfSegment Elf (ElfSegmentXX a)

data ElfXX (c :: ElfClass) where
    Elf64 ::
        { elf64Entry    :: Word64
        , elf64Segments :: [ElfSegmentXX c]
        , elf64Sections :: [ElfSectionXX c]
        } -> ElfXX 'ELFCLASS64
    Elf32 ::
        { elf32Entry    :: Word32
        , elf32Segments :: [ElfSegmentXX c]
        , elf32Sections :: [ElfSectionXX c]
        } -> ElfXX 'ELFCLASS32

-- FIXME: fix this crap
class ElfXXTools (c :: ElfClass) w | c -> w where
    mkElfXX :: Proxy c -> w -> [ElfSegmentXX c] -> [ElfSectionXX c] -> ElfXX c

instance ElfXXTools ELFCLASS32 Word32 where
    mkElfXX _ = Elf32

instance ElfXXTools ELFCLASS64 Word64 where
    mkElfXX _ = Elf64

data Elf =
    forall (c :: ElfClass) . Elf
        { elfData       :: ElfData       -- ^ Identifies the data encoding of the object file (endianness).
        , elfOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
        , elfABIVersion :: Word8         -- ^ Identifies the ABI version for which the object is prepared.
        , elfType       :: ElfType       -- ^ Identifies the object file type.
        , elfMachine    :: ElfMachine    -- ^ Identifies the target architecture.
        , elfFlags      :: Word32
        , elfShstrndx   :: Word16
        , elfXX         :: ElfXX c
        , elfContent    :: B.ByteString
        }

instance Binary Elf where
    put = undefined
    get = getElf

elfSupportedVersion :: Word8
elfSupportedVersion = 1

elfVersion :: Elf -> Word8
elfVersion _ = elfSupportedVersion

elfClass :: Elf -> ElfClass
elfClass (Elf { elfXX = Elf64 {} }) = ELFCLASS64
elfClass (Elf { elfXX = Elf32 {} }) = ELFCLASS32

elfEntry :: Elf -> Word64
elfEntry (Elf { elfXX = Elf64 { elf64Entry = e } }) = e
elfEntry (Elf { elfXX = Elf32 { elf32Entry = e } }) = fromIntegral e

elfSections :: Elf -> [ElfSection]
elfSections e@(Elf { elfXX = Elf64 { elf64Sections = s } }) = fmap (ElfSection e) s
elfSections e@(Elf { elfXX = Elf32 { elf32Sections = s } }) = fmap (ElfSection e) s

elfSegments :: Elf -> [ElfSegment]
elfSegments e@(Elf { elfXX = Elf64 { elf64Segments = s } }) = fmap (ElfSegment e) s
elfSegments e@(Elf { elfXX = Elf32 { elf32Segments = s } }) = fmap (ElfSegment e) s

at :: (Integral i) => [a] -> i -> Maybe a
at (x : _)  0             = Just x
at (_ : xs) n | n > 0     = xs `at` (n - 1)
              | otherwise = Nothing
at _        _             = Nothing

getStringSection :: Elf -> Maybe B.ByteString
getStringSection elf@(Elf {..}) = elfSectionData <$> elfSections elf `at` elfShstrndx

getString :: Elf -> Word32 -> Maybe String
getString elf offset = C.unpack <$> B.takeWhile (/= 0) <$> B.drop (fromIntegral offset) <$> getStringSection elf

elfSectionName :: ElfSection -> String -- ^ Identifies the name of the section.
elfSectionName (ElfSection elf (ElfSection64 { elf64SectionName = n } )) = maybe "" id $ getString elf n
elfSectionName (ElfSection elf (ElfSection32 { elf32SectionName = n } )) = maybe "" id $ getString elf n

elfSectionType :: ElfSection -> ElfSectionType -- ^ Identifies the name of the section.
elfSectionType (ElfSection _ (ElfSection64 { elf64SectionType = t } )) = t
elfSectionType (ElfSection _ (ElfSection32 { elf32SectionType = t } )) = t

elfSectionFlags :: ElfSection -> ElfSectionFlag -- ^ Identifies the attributes of the section.
elfSectionFlags (ElfSection _ (ElfSection64 { elf64SectionFlags = f } )) = ElfSectionFlag f
elfSectionFlags (ElfSection _ (ElfSection32 { elf32SectionFlags = f } )) = ElfSectionFlag $ fromIntegral f

elfSectionAddr :: ElfSection -> Word64 -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
elfSectionAddr (ElfSection _ (ElfSection64 { elf64SectionAddr = a } )) = a
elfSectionAddr (ElfSection _ (ElfSection32 { elf32SectionAddr = a } )) = fromIntegral a

elfSectionSize :: ElfSection -> Word64 -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
elfSectionSize (ElfSection _ (ElfSection64 { elf64SectionSize = a } )) = a
elfSectionSize (ElfSection _ (ElfSection32 { elf32SectionSize = a } )) = fromIntegral a

elfSectionLink :: ElfSection -> Word32 -- ^ Contains a section index of an associated section, depending on section type.
elfSectionLink (ElfSection _ (ElfSection64 { elf64SectionLink = a } )) = a
elfSectionLink (ElfSection _ (ElfSection32 { elf32SectionLink = a } )) = a

elfSectionInfo :: ElfSection -> Word32 -- ^ Contains extra information for the index, depending on type.
elfSectionInfo (ElfSection _ (ElfSection64 { elf64SectionInfo = a } )) = a
elfSectionInfo (ElfSection _ (ElfSection32 { elf32SectionInfo = a } )) = a

elfSectionAddrAlign :: ElfSection -> Word64 -- ^ Contains the required alignment of the section. Must be a power of two.
elfSectionAddrAlign (ElfSection _ (ElfSection64 { elf64SectionAddrAlign = a } )) = a
elfSectionAddrAlign (ElfSection _ (ElfSection32 { elf32SectionAddrAlign = a } )) = fromIntegral a

elfSectionEntSize :: ElfSection -> Word64 -- ^ Size of entries if section has a table.
elfSectionEntSize (ElfSection _ (ElfSection64 { elf64SectionEntSize = a } )) = a
elfSectionEntSize (ElfSection _ (ElfSection32 { elf32SectionEntSize = a } )) = fromIntegral a

-- FIXME: this can fail on 32 bit machine working with 64 bit elfs
getData :: Elf -> Int -> Int -> B.ByteString
getData (Elf {elfContent = c}) o s = B.take s $ B.drop o c

elfSectionData :: ElfSection -> B.ByteString -- ^ The raw data for the section.
elfSectionData (ElfSection elf (ElfSection64 { elf64SectionOffset = o, elf64SectionSize = s })) = getData elf (fromIntegral o) (fromIntegral s)
elfSectionData (ElfSection elf (ElfSection32 { elf32SectionOffset = o, elf32SectionSize = s })) = getData elf (fromIntegral o) (fromIntegral s)

elfSegmentType :: ElfSegment -> ElfSegmentType -- ^ Segment type
elfSegmentType (ElfSegment _ (ElfSegment64 { elf64SegmentType = a } )) = a
elfSegmentType (ElfSegment _ (ElfSegment32 { elf32SegmentType = a } )) = a

elfSegmentFlags :: ElfSegment -> ElfSegmentFlag -- ^ Segment flags
elfSegmentFlags (ElfSegment _ (ElfSegment64 { elf64SegmentFlags = a } )) = ElfSegmentFlag a
elfSegmentFlags (ElfSegment _ (ElfSegment32 { elf32SegmentFlags = a } )) = ElfSegmentFlag a

elfSegmentVirtAddr :: ElfSegment -> Word64 -- ^ Virtual address for the segment
elfSegmentVirtAddr (ElfSegment _ (ElfSegment64 { elf64SegmentVirtAddr = a } )) = a
elfSegmentVirtAddr (ElfSegment _ (ElfSegment32 { elf32SegmentVirtAddr = a } )) = fromIntegral a

elfSegmentPhysAddr :: ElfSegment -> Word64 -- ^ Physical address for the segment
elfSegmentPhysAddr (ElfSegment _ (ElfSegment64 { elf64SegmentPhysAddr = a } )) = a
elfSegmentPhysAddr (ElfSegment _ (ElfSegment32 { elf32SegmentPhysAddr = a } )) = fromIntegral a

elfSegmentAlign :: ElfSegment -> Word64 -- ^ Segment alignment
elfSegmentAlign (ElfSegment _ (ElfSegment64 { elf64SegmentAlign = a } )) = a
elfSegmentAlign (ElfSegment _ (ElfSegment32 { elf32SegmentAlign = a } )) = fromIntegral a

elfSegmentData :: ElfSegment -> B.ByteString -- ^ Data for the segment
elfSegmentData (ElfSegment elf (ElfSegment64 { elf64SegmentOffset = o, elf64SegmentFileSize = s })) = getData elf (fromIntegral o) (fromIntegral s)
elfSegmentData (ElfSegment elf (ElfSegment32 { elf32SegmentOffset = o, elf32SegmentFileSize = s })) = getData elf (fromIntegral o) (fromIntegral s)

elfSegmentMemSize :: ElfSegment -> Word64 -- ^ Size in memory  (may be larger then the segment's data)
elfSegmentMemSize (ElfSegment _ (ElfSegment64 { elf64SegmentMemSize = a } )) = a
elfSegmentMemSize (ElfSegment _ (ElfSegment32 { elf32SegmentMemSize = a } )) = fromIntegral a

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

getXX :: forall proxy b w . (Integral w,
                             Num b,
                             Binary (Le w), Binary (Be w))
         => proxy w
         -> ElfData
         -> Get b
getXX _ e_data = (fromIntegral :: w -> b) <$> getEndian e_data

getElf' :: forall c w . (ElfXXTools c w,
                         Integral w,
                         Binary (Le w), Binary (Be w),
                         Binary (Le (ElfSegmentXX c)), Binary (Be (ElfSegmentXX c)),
                         Binary (Le (ElfSectionXX c)), Binary (Be (ElfSectionXX c)))
        => Proxy (c :: ElfClass)
        -> B.ByteString
        -> ElfData
        -> Get Elf
getElf' p e_content e_data = do

    let
        getE :: (Binary (Le a), Binary (Be a)) => Get a
        getE = getEndian e_data

    verify "version1" elfSupportedVersion
    e_osabi     <- get
    e_abiver    <- get
    skip 7
    e_type      <- getE
    e_machine   <- getE

    e_version2  <- getE
    when (e_version2 /= (1 :: Word32)) $ error "verification failed: version2"

    e_entry     <- getE

    e_phoff     <- getXX (Proxy :: Proxy w) e_data
    e_shoff     <- getXX (Proxy :: Proxy w) e_data

    e_flags     <- getE

    (e_ehsize :: Word16) <- getE

    e_phentsize <- getE
    e_phnum     <- getE
    e_shentsize <- getE
    e_shnum     <- getE

    e_shstrndx  <- getE

    hSize <- bytesRead
    when (hSize /= fromIntegral e_ehsize) $ error "incorrect size of elf header"

    e_xx <- mkElfXX p e_entry <$> getTable e_data (e_phoff - fromIntegral e_ehsize) e_phentsize e_phnum
                              <*> getTable e_data (e_shoff - fromIntegral e_ehsize) e_shentsize e_shnum

    return $ Elf
        { elfData = e_data
        , elfOSABI = e_osabi
        , elfABIVersion = e_abiver
        , elfType = e_type
        , elfMachine = e_machine
        , elfFlags = e_flags
        , elfShstrndx = e_shstrndx
        , elfXX = e_xx
        , elfContent = e_content
        }

getElf :: Get Elf
getElf = do

    e_content <- L.toStrict <$> lookAhead getRemainingLazyByteString

    verify "magic" elfMagic
    e_class    <- get
    e_data     <- get

    (case e_class of
        ELFCLASS32 -> getElf' (Proxy :: Proxy 'ELFCLASS32)
        ELFCLASS64 -> getElf' (Proxy :: Proxy 'ELFCLASS64)) e_content e_data

getElfSection64 :: (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get (ElfSectionXX 'ELFCLASS64)
getElfSection64 getE = ElfSection64 <$> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE

getElfSection32 :: (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get (ElfSectionXX 'ELFCLASS32)
getElfSection32 getE = ElfSection32 <$> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE

getElfSegment64 :: (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get (ElfSegmentXX 'ELFCLASS64)
getElfSegment64 getE = ElfSegment64 <$> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE

getElfSegment32 :: (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get (ElfSegmentXX 'ELFCLASS32)
getElfSegment32 getE = ElfSegment32 <$> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE
                                    <*> getE

splitBits :: (Num w, FiniteBits w) => w -> [w]
splitBits w = map (shiftL 1) $ filter (testBit w) $ map (subtract 1) [ 1 .. (finiteBitSize w) ]

-- getElf_Shdr_OffsetSize :: ElfClass -> ElfReader -> Get (Word64, Word64)
-- getElf_Shdr_OffsetSize ei_class er =
--     case ei_class of
--         ELFCLASS32 -> do
--             skip 16
--             sh_offset <- liftM fromIntegral $ getWord32 er
--             sh_size   <- liftM fromIntegral $ getWord32 er
--             return (sh_offset, sh_size)
--         ELFCLASS64 -> do
--             skip 24
--             sh_offset <- getWord64 er
--             sh_size   <- getWord64 er
--             return (sh_offset, sh_size)

-- getElf_Shdr :: ElfData -> ElfClass -> ElfReader -> B.ByteString -> B.ByteString -> Get ElfSection
-- getElf_Shdr ei_data ei_class er elf_file string_section =
--     case ei_class of
--         ELFCLASS32 -> do
--             sh_name      <- getWord32 er
--             sh_type      <- getE ei_data
--             sh_flags     <- id32to64 <$> getE ei_data
--             sh_addr      <- getWord32 er
--             sh_offset    <- getWord32 er
--             sh_size      <- getWord32 er
--             sh_link      <- getWord32 er
--             sh_info      <- getWord32 er
--             sh_addralign <- getWord32 er
--             sh_entsize   <- getWord32 er
--             return ElfSection
--                 { elfSectionName      = map B.w2c $ B.unpack $ B.takeWhile (/= 0) $ B.drop (fromIntegral sh_name) string_section
--                 , elfSectionType      = sh_type
--                 , elfSectionFlagsW    = sh_flags
--                 , elfSectionAddr      = fromIntegral sh_addr
--                 , elfSectionSize      = fromIntegral sh_size
--                 , elfSectionLink      = sh_link
--                 , elfSectionInfo      = sh_info
--                 , elfSectionAddrAlign = fromIntegral sh_addralign
--                 , elfSectionEntSize   = fromIntegral sh_entsize
--                 , elfSectionData      = B.take (fromIntegral sh_size) $ B.drop (fromIntegral sh_offset) elf_file
--                 }
--         ELFCLASS64 -> do
--             sh_name      <- getWord32 er
--             sh_type      <- getE ei_data
--             sh_flags     <- getE ei_data
--             sh_addr      <- getWord64 er
--             sh_offset    <- getWord64 er
--             sh_size      <- getWord64 er
--             sh_link      <- getWord32 er
--             sh_info      <- getWord32 er
--             sh_addralign <- getWord64 er
--             sh_entsize   <- getWord64 er
--             return ElfSection
--                 { elfSectionName      = map B.w2c $ B.unpack $ B.takeWhile (/= 0) $ B.drop (fromIntegral sh_name) string_section
--                 , elfSectionType      = sh_type
--                 , elfSectionFlagsW    = sh_flags
--                 , elfSectionAddr      = sh_addr
--                 , elfSectionSize      = sh_size
--                 , elfSectionLink      = sh_link
--                 , elfSectionInfo      = sh_info
--                 , elfSectionAddrAlign = sh_addralign
--                 , elfSectionEntSize   = sh_entsize
--                 , elfSectionData      = B.take (fromIntegral sh_size) $ B.drop (fromIntegral sh_offset) elf_file
--                 }

-- data TableInfo = TableInfo { tableOffset :: Int, entrySize :: Int, entryNum :: Int }

-- getElf_Ehdr :: Get (Elf, TableInfo, TableInfo, Word16)
-- getElf_Ehdr = do
--     verifyElfMagic
--     ei_class    <- get
--     ei_data     <- get
--     verifyElfVersion
--     ei_osabi    <- get
--     ei_abiver   <- get
--     skip 7
--     er          <- return $ elfReader ei_data
--     e_type      <- getE ei_data
--     e_machine   <- getE ei_data
--     _           <- getWord32 er
--     case ei_class of
--         ELFCLASS32 -> do
--             e_entry     <- liftM fromIntegral $ getWord32 er
--             e_phoff     <- getWord32 er
--             e_shoff     <- getWord32 er
--             _           <- getWord32 er
--             _           <- getWord16 er
--             e_phentsize <- getWord16 er
--             e_phnum     <- getWord16 er
--             e_shentsize <- getWord16 er
--             e_shnum     <- getWord16 er
--             e_shstrndx  <- getWord16 er
--             return (Elf { elfClass      = ei_class
--                         , elfData       = ei_data
--                         , elfOSABI      = ei_osabi
--                         , elfABIVersion = ei_abiver
--                         , elfType       = e_type
--                         , elfMachine    = e_machine
--                         , elfEntry      = e_entry
--                         , elfSections   = []
--                         , elfSegments   = [] }
--                    , TableInfo { tableOffset = fromIntegral e_phoff, entrySize = fromIntegral e_phentsize, entryNum = fromIntegral e_phnum }
--                    , TableInfo { tableOffset = fromIntegral e_shoff, entrySize = fromIntegral e_shentsize, entryNum = fromIntegral e_shnum }
--                    , e_shstrndx)
--         ELFCLASS64 -> do
--             e_entry     <- getWord64 er
--             e_phoff     <- getWord64 er
--             e_shoff     <- getWord64 er
--             _           <- getWord32 er
--             _           <- getWord16 er
--             e_phentsize <- getWord16 er
--             e_phnum     <- getWord16 er
--             e_shentsize <- getWord16 er
--             e_shnum     <- getWord16 er
--             e_shstrndx  <- getWord16 er
--             return (Elf { elfClass      = ei_class
--                         , elfData       = ei_data
--                         , elfOSABI      = ei_osabi
--                         , elfABIVersion = ei_abiver
--                         , elfType       = e_type
--                         , elfMachine    = e_machine
--                         , elfEntry      = e_entry
--                         , elfSections   = []
--                         , elfSegments   = [] }
--                    , TableInfo { tableOffset = fromIntegral e_phoff, entrySize = fromIntegral e_phentsize, entryNum = fromIntegral e_phnum }
--                    , TableInfo { tableOffset = fromIntegral e_shoff, entrySize = fromIntegral e_shentsize, entryNum = fromIntegral e_shnum }
--                    , e_shstrndx)

data ElfReader = ElfReader
    { getWord16 :: Get Word16
    , getWord32 :: Get Word32
    , getWord64 :: Get Word64
    }

elfReader :: ElfData -> ElfReader
elfReader ELFDATA2LSB = ElfReader { getWord16 = getWord16le, getWord32 = getWord32le, getWord64 = getWord64le }
elfReader ELFDATA2MSB = ElfReader { getWord16 = getWord16be, getWord32 = getWord32be, getWord64 = getWord64be }

-- divide :: B.ByteString -> Int -> Int -> [B.ByteString]
-- divide  _ _ 0 = []
-- divide bs s n = let (x,y) = B.splitAt s bs in x : divide y s (n-1)

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects have their
-- fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> Elf
parseElf b = decode $ L.fromChunks [b]
--     let ph                                             = table segTab
--         sh                                             = table secTab
--         (shstroff, shstrsize)                          = parseEntry getElf_Shdr_OffsetSize $ head $ drop (fromIntegral e_shstrndx) sh
--         sh_str                                         = B.take (fromIntegral shstrsize) $ B.drop (fromIntegral shstroff) b
--         segments                                       = map (parseEntry (\c r -> parseElfSegmentEntry (elfData e) c r b)) ph
--         sections                                       = map (parseEntry (\c r -> getElf_Shdr (elfData e) c r b sh_str)) sh
--     in e { elfSections = sections, elfSegments = segments }

--   where table i                         = divide (B.drop (tableOffset i) b) (entrySize i) (entryNum i)
--         parseEntry p x                  = runGet (p (elfClass e) (elfReader (elfData e))) (L.fromChunks [x])
--         (e, segTab, secTab, e_shstrndx) = runGet getElf_Ehdr $ L.fromChunks [b]

-- parseElfSegmentEntry :: ElfData -> ElfClass -> ElfReader -> B.ByteString -> Get ElfSegment
-- parseElfSegmentEntry ei_data elf_class er elf_file = case elf_class of
--   ELFCLASS64 -> do
--      p_type   <- getE ei_data
--      p_flags  <- getE ei_data
--      p_offset <- getWord64 er
--      p_vaddr  <- getWord64 er
--      p_paddr  <- getWord64 er
--      p_filesz <- getWord64 er
--      p_memsz  <- getWord64 er
--      p_align  <- getWord64 er
--      return ElfSegment
--        { elfSegmentType     = p_type
--        , elfSegmentFlagsW   = p_flags
--        , elfSegmentVirtAddr = p_vaddr
--        , elfSegmentPhysAddr = p_paddr
--        , elfSegmentAlign    = p_align
--        , elfSegmentData     = B.take (fromIntegral p_filesz) $ B.drop (fromIntegral p_offset) elf_file
--        , elfSegmentMemSize  = p_memsz
--        }

--   ELFCLASS32 -> do
--      p_type   <- getE ei_data
--      p_offset <- fromIntegral `fmap` getWord32 er
--      p_vaddr  <- fromIntegral `fmap` getWord32 er
--      p_paddr  <- fromIntegral `fmap` getWord32 er
--      p_filesz <- fromIntegral `fmap` getWord32 er
--      p_memsz  <- fromIntegral `fmap` getWord32 er
--      p_flags  <- getE ei_data
--      p_align  <- fromIntegral `fmap` getWord32 er
--      return ElfSegment
--        { elfSegmentType     = p_type
--        , elfSegmentFlagsW   = p_flags
--        , elfSegmentVirtAddr = p_vaddr
--        , elfSegmentPhysAddr = p_paddr
--        , elfSegmentAlign    = p_align
--        , elfSegmentData     = B.take p_filesz $ B.drop p_offset elf_file
--        , elfSegmentMemSize  = p_memsz
--        }

-- | The symbol table entries consist of index information to be read from other
-- parts of the ELF file. Some of this information is automatically retrieved
-- for your convenience (including symbol name, description of the enclosing
-- section, and definition).
data ElfSymbolTableEntry = EST
    { steName             :: (Word32,Maybe B.ByteString)
--    , steEnclosingSection :: Maybe ElfSection -- ^ Section from steIndex
    , steType             :: ElfSymbolType
    , steBind             :: ElfSymbolBinding
    , steOther            :: Word8
    , steIndex            :: ElfSectionIndex  -- ^ Section in which the def is held
    , steValue            :: Word64
    , steSize             :: Word64
    } deriving (Eq, Show)

-- | Parse the symbol table section into a list of symbol table entries. If
-- no symbol table is found then an empty list is returned.
-- This function does not consult flags to look for SHT_STRTAB (when naming symbols),
-- it just looks for particular sections of ".strtab" and ".shstrtab".
parseSymbolTables :: Elf -> [[ElfSymbolTableEntry]]
parseSymbolTables e =
    let secs = symbolTableSections e
    in map (getSymbolTableEntries e) secs

-- | Assumes the given section is a symbol table, type SHT_SYMTAB, or SHT_DYNSYM
-- (guaranteed by parseSymbolTables).
getSymbolTableEntries :: Elf -> ElfSection -> [ElfSymbolTableEntry]
getSymbolTableEntries e s = go decoder (L.fromChunks [elfSectionData s])
  where
    link   = elfSectionLink s
    strtab = lookup link (zip [0..] (elfSections e))
    decoder = runGetIncremental (getSymbolTableEntry e strtab)
    go :: Decoder ElfSymbolTableEntry -> L.ByteString -> [ElfSymbolTableEntry]
    go (Done leftover _ entry) input =
      entry : go decoder (L.Chunk leftover input)
    go (Partial k) input =
      go (k . takeHeadChunk $ input) (dropHeadChunk input)
    go (Fail _ _ msg) input = if L.null input
                              then []
                              else error msg

takeHeadChunk :: L.ByteString -> Maybe B.ByteString
takeHeadChunk lbs =
  case lbs of
    (L.Chunk bs _) -> Just bs
    _ -> Nothing

dropHeadChunk :: L.ByteString -> L.ByteString
dropHeadChunk lbs =
  case lbs of
    (L.Chunk _ lbs') -> lbs'
    _ -> L.Empty

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

symbolTableSections :: Elf -> [ElfSection]
symbolTableSections e = filter ((`elem` [SHT_SYMTAB, SHT_DYNSYM]) . elfSectionType) (elfSections e)

-- | Gets a single entry from the symbol table, use with runGetMany.
getSymbolTableEntry :: Elf -> Maybe ElfSection -> Get ElfSymbolTableEntry
getSymbolTableEntry e strtlb =
    if elfClass e == ELFCLASS32 then getSymbolTableEntry32 else getSymbolTableEntry64
  where
  strs = maybe B.empty elfSectionData strtlb
  er = elfReader (elfData e)
  getSymbolTableEntry32 = do
    nameIdx <- liftM fromIntegral (getWord32 er)
    value <- liftM fromIntegral (getWord32 er)
    size  <- liftM fromIntegral (getWord32 er)
    info  <- getWord8
    other <- getWord8
    sTlbIdx <- liftM (toEnum . fromIntegral) (getWord16 er)
    let name = stringByIndex nameIdx strs
        (typ,bind) = infoToTypeAndBind info
        -- sec = sectionByIndex e sTlbIdx
    return $ EST (nameIdx,name) typ bind other sTlbIdx value size
  getSymbolTableEntry64 = do
    nameIdx <- liftM fromIntegral (getWord32 er)
    info <- getWord8
    other <- getWord8
    sTlbIdx <- liftM (toEnum . fromIntegral) (getWord16 er)
    symVal <- getWord64 er
    size <- getWord64 er
    let name = stringByIndex nameIdx strs
        (typ,bind) = infoToTypeAndBind info
        -- sec = sectionByIndex e sTlbIdx
    return $ EST (nameIdx,name) typ bind other sTlbIdx symVal size

sectionByIndex :: Elf -> ElfSectionIndex -> Maybe ElfSection
sectionByIndex e (SHNIndex i) = lookup i . zip [0..] $ elfSections e
sectionByIndex _ _ = Nothing

infoToTypeAndBind :: Word8 -> (ElfSymbolType,ElfSymbolBinding)
infoToTypeAndBind i =
    let t = fromIntegral $ i .&. 0x0F
        b = fromIntegral $ (i .&. 0xF0) `shiftR` 4
    in (toEnum t, toEnum b)

data ElfSymbolBinding
    = STBLocal
    | STBGlobal
    | STBWeak
    | STBLoOS
    | STBHiOS
    | STBLoProc
    | STBHiProc
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSymbolBinding where
    fromEnum STBLocal  = 0
    fromEnum STBGlobal = 1
    fromEnum STBWeak   = 2
    fromEnum STBLoOS   = 10
    fromEnum STBHiOS   = 12
    fromEnum STBLoProc = 13
    fromEnum STBHiProc = 15
    toEnum  0 = STBLocal
    toEnum  1 = STBGlobal
    toEnum  2 = STBWeak
    toEnum 10 = STBLoOS
    toEnum 12 = STBHiOS
    toEnum 13 = STBLoProc
    toEnum 15 = STBHiProc
    toEnum  _ = STBLocal -- FIXME

data ElfSymbolType
    = STTNoType
    | STTObject
    | STTFunc
    | STTSection
    | STTFile
    | STTCommon
    | STTTLS
    | STTLoOS
    | STTHiOS
    | STTLoProc
    | STTHiProc
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSymbolType where
    fromEnum STTNoType  = 0
    fromEnum STTObject  = 1
    fromEnum STTFunc    = 2
    fromEnum STTSection = 3
    fromEnum STTFile    = 4
    fromEnum STTCommon  = 5
    fromEnum STTTLS     = 6
    fromEnum STTLoOS    = 10
    fromEnum STTHiOS    = 12
    fromEnum STTLoProc  = 13
    fromEnum STTHiProc  = 15
    toEnum  0 = STTNoType
    toEnum  1 = STTObject
    toEnum  2 = STTFunc
    toEnum  3 = STTSection
    toEnum  4 = STTFile
    toEnum  5 = STTCommon
    toEnum  6 = STTTLS
    toEnum 10 = STTLoOS
    toEnum 12 = STTHiOS
    toEnum 13 = STTLoProc
    toEnum 15 = STTHiProc
    toEnum  _ = STTNoType

data ElfSectionIndex
    = SHNUndef
    | SHNLoProc
    | SHNCustomProc Word64
    | SHNHiProc
    | SHNLoOS
    | SHNCustomOS Word64
    | SHNHiOS
    | SHNAbs
    | SHNCommon
    | SHNIndex Word64
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSectionIndex where
    fromEnum SHNUndef = 0
    fromEnum SHNLoProc = 0xFF00
    fromEnum SHNHiProc = 0xFF1F
    fromEnum SHNLoOS   = 0xFF20
    fromEnum SHNHiOS   = 0xFF3F
    fromEnum SHNAbs    = 0xFFF1
    fromEnum SHNCommon = 0xFFF2
    fromEnum (SHNCustomProc x) = fromIntegral x
    fromEnum (SHNCustomOS x) = fromIntegral x
    fromEnum (SHNIndex x) = fromIntegral x
    toEnum 0 = SHNUndef
    toEnum 0xff00 = SHNLoProc
    toEnum 0xFF1F = SHNHiProc
    toEnum 0xFF20 = SHNLoOS
    toEnum 0xFF3F = SHNHiOS
    toEnum 0xFFF1 = SHNAbs
    toEnum 0xFFF2 = SHNCommon
    toEnum x
        | x > fromEnum SHNLoProc && x < fromEnum SHNHiProc = SHNCustomProc (fromIntegral x)
        | x > fromEnum SHNLoOS && x < fromEnum SHNHiOS = SHNCustomOS (fromIntegral x)
        | x < fromEnum SHNLoProc || x > 0xFFFF = SHNIndex (fromIntegral x)
        | otherwise = error "Section index number is in a reserved range but we don't recognize the value from any standard."

-- | Given a section name, extract the ElfSection.
findSectionByName :: String -> Elf -> Maybe ElfSection
findSectionByName name = listToMaybe . filter ((==) name . elfSectionName) . elfSections

-- Get a string from a strtab ByteString.
stringByIndex :: Integral n => n -> B.ByteString -> Maybe B.ByteString
stringByIndex n strtab =
    let str = (B.takeWhile (/=0) . B.drop (fromIntegral n)) strtab
    in if B.length str == 0 then Nothing else Just str
