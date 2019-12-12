{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Data.Elf is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf ( parseSymbolTables
                , findSymbolDefinition
                , findSectionByName

                , Elf(..)
                , elfVersion
                , elfClass

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
                , elfSegmentFlags

                , ElfClass(..)
                , ElfData(..)

                , ElfSymbolTableEntry(..)
                , ElfSymbolType(..)
                , ElfSymbolBinding(..)
                , ElfSectionIndex(..)
                , module Data.Elf.Generated) where

import Data.Binary
import Data.Binary.Get as G
import Data.Bits
import Data.Maybe
import Control.Monad
import qualified Data.ByteString               as B
import qualified Data.ByteString.Lazy          as L
import qualified Data.ByteString.Lazy.Internal as L

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

data ElfXX
    = Elf32
        { e32Segments   :: [ElfSegment32]  -- ^ List of segments in the file.
        , e32Sections   :: [ElfSection32]  -- ^ List of sections in the file.
        }
    | Elf64
        { e64Segments   :: [ElfSegment64]  -- ^ List of segments in the file.
        , e64Sections   :: [ElfSection64]  -- ^ List of sections in the file.
        } deriving (Eq, Show)

fromW32 :: Num b => Word32 -> b
fromW32 = fromIntegral

data Elf = Elf
    -- elfClass is encoded with constructors of ElfXX
    { elfData       :: ElfData       -- ^ Identifies the data encoding of the object file (endianness).
    , elfOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
    , elfABIVersion :: Word8         -- ^ Identifies the ABI version for which the object is prepared.
    , elfType       :: ElfType       -- ^ Identifies the object file type.
    , elfMachine    :: ElfMachine    -- ^ Identifies the target architecture.
    , elfEntry      :: Word64
    , elfFlags      :: Word32
    , elfShstrndx   :: Word16
    , elfXX         :: ElfXX
    , elfContent    :: [ (Word64, B.ByteString) ]
    } deriving (Eq, Show)

verify :: (Binary a, Eq a) => String -> a -> Get ()
verify msg orig = do
    a <- get
    when (orig /= a) $ error ("verification failed: " ++ msg)

getTable :: (Binary (Le a), Binary (Be a)) => ElfData -> Word64 -> Word16 -> Word16 -> Get [a]
getTable endianness offset entrySize entryNumber = lookAhead $ do
    skip $ fromIntegral offset
    take (fromIntegral entryNumber) <$> getTable'
    where
        getTable' = do
            a <- isolate (fromIntegral entrySize) $ getEndian endianness
            (a : ) <$> getTable'

getElf :: Get Elf
getElf = do
    verify "magic" elfMagic
    ei_class    <- get
    ei_data     <- get

    let 
        getE :: (Binary (Le a), Binary (Be a)) => Get a
        getE = getEndian ei_data

        get64_32 = case ei_class of
            ELFCLASS32 -> fromW32 <$> getE
            ELFCLASS64 ->             getE

    verify "version1" elfSupportedVersion
    ei_osabi    <- get
    ei_abiver   <- get
    skip 7
    e_type      <- getE
    e_machine   <- getE

    e_version2  <- getE
    when (e_version2 /= (1 :: Word32)) $ error "verification failed: version2"

    e_entry     <- get64_32
    e_phoff     <- get64_32
    e_shoff     <- get64_32

    e_flags     <- getE

    e_ehsize    <- getE

    e_phentsize <- getE
    e_phnum     <- getE
    e_shentsize <- getE
    e_shnum     <- getE

    e_shstrndx  <- getE

    hSize <- bytesRead
    when (hSize /= fromIntegral (e_ehsize :: Word16)) $ error "incorrect size of elf header"

    e_xx <- case ei_class of
        ELFCLASS32 -> Elf32 <$> getTable ei_data (e_phoff - fromIntegral e_ehsize) e_phentsize e_phnum
                            <*> getTable ei_data (e_shoff - fromIntegral e_ehsize) e_shentsize e_shnum
        ELFCLASS64 -> Elf64 <$> getTable ei_data (e_phoff - fromIntegral e_ehsize) e_phentsize e_phnum
                            <*> getTable ei_data (e_shoff - fromIntegral e_ehsize) e_shentsize e_shnum

    return $ Elf
        { elfData = ei_data
        , elfOSABI = ei_osabi
        , elfABIVersion = ei_abiver
        , elfType = e_type
        , elfMachine = e_machine
        , elfEntry = e_entry
        , elfFlags = e_flags
        , elfShstrndx = e_shstrndx
        , elfXX = e_xx
        , elfContent = []
        }

instance Binary Elf where
    put = undefined
    get = getElf

elfVersion :: Elf -> Word8
elfVersion _ = elfSupportedVersion

elfClass :: Elf -> ElfClass
elfClass (Elf { elfXX = Elf32 {} }) = ELFCLASS32
elfClass (Elf { elfXX = Elf64 {} }) = ELFCLASS64

elfSections :: Elf -> [ElfSection]
elfSections e @ (Elf { elfXX = Elf32 { e32Sections = s } }) = map (S32 e) s
elfSections e @ (Elf { elfXX = Elf64 { e64Sections = s } }) = map (S64 e) s

elfSegments :: Elf -> [ElfSegment]
elfSegments e @ (Elf { elfXX = Elf32 { e32Segments = s } }) = map (P32 e) s
elfSegments e @ (Elf { elfXX = Elf64 { e64Segments = s } }) = map (P64 e) s

data ElfSection
    = S32 { s32elf :: Elf, s32section :: ElfSection32 }
    | S64 { s64elf :: Elf, s64section :: ElfSection64 }

data ElfSegment
    = P32 { p32elf :: Elf, p32segment :: ElfSegment32 }
    | P64 { p64elf :: Elf, p64segment :: ElfSegment64 }

-- elfSectionElf :: ElfSection -> Elf
-- elfSectionElf S32 { s32elf = e } = e
-- elfSectionElf S64 { s64elf = e } = e

elfSectionName :: ElfSection -> String
elfSectionName = undefined

elfSectionType :: ElfSection -> ElfSectionType
elfSectionType (S32 { s32section = ElfSection32 { sh32Type = t } }) = t
elfSectionType (S64 { s64section = ElfSection64 { sh64Type = t } }) = t

elfSectionFlags :: ElfSection -> [ElfSectionFlag]
elfSectionFlags (S32 { s32section = ElfSection32 { sh32Flags = f } }) = map ElfSectionFlag $ splitBits $ fromIntegral f
elfSectionFlags (S64 { s64section = ElfSection64 { sh64Flags = f } }) = map ElfSectionFlag $ splitBits                f

elfSectionAddr :: ElfSection -> Word64
elfSectionAddr = undefined

elfSectionSize :: ElfSection -> Word64
elfSectionSize = undefined

elfSectionLink :: ElfSection -> Word32
elfSectionLink = undefined

elfSectionInfo :: ElfSection -> Word32
elfSectionInfo = undefined

elfSectionAddrAlign :: ElfSection -> Word64
elfSectionAddrAlign = undefined

elfSectionEntSize :: ElfSection -> Word64
elfSectionEntSize = undefined

elfSectionData :: ElfSection -> B.ByteString
elfSectionData = undefined

elfSegmentFlags :: ElfSegment -> [ElfSegmentFlag]
elfSegmentFlags (P32 { p32segment = ElfSegment32 { p32Flags = f } }) = map ElfSegmentFlag $ splitBits f
elfSegmentFlags (P64 { p64segment = ElfSegment64 { p64Flags = f } }) = map ElfSegmentFlag $ splitBits f

data ElfSection64 = ElfSection64
    { sh64Name      :: Word32
    , sh64Type      :: ElfSectionType    -- ^ Identifies the type of the section.
    , sh64Flags     :: Word64            -- ^ Identifies the attributes of the section.
    , sh64Addr      :: Word64            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
    , sh64Offset    :: Word64
    , sh64Size      :: Word64            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
    , sh64Link      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
    , sh64Info      :: Word32            -- ^ Contains extra information for the index, depending on type.
    , sh64AddrAlign :: Word64            -- ^ Contains the required alignment of the section. Must be a power of two.
    , sh64EntSize   :: Word64            -- ^ Size of entries if section has a table.
    } deriving (Eq, Show)

getElfSection64 :: (forall a . (Binary (Le a), Binary (Be a)) => Get a) -> Get ElfSection64
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

instance Binary (Be ElfSection64) where
    put = undefined
    get = Be <$> (getElfSection64 $ getEndian ELFDATA2MSB)

instance Binary (Le ElfSection64) where
    put = undefined
    get = Le <$> (getElfSection64 $ getEndian ELFDATA2LSB)

data ElfSection32 = ElfSection32
    { sh32Name      :: Word32
    , sh32Type      :: ElfSectionType    -- ^ Identifies the type of the section.
    , sh32Flags     :: Word32            -- ^ Identifies the attributes of the section.
    , sh32Addr      :: Word32            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
    , sh32Offset    :: Word32
    , sh32Size      :: Word32            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
    , sh32Link      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
    , sh32Info      :: Word32            -- ^ Contains extra information for the index, depending on type.
    , sh32AddrAlign :: Word32            -- ^ Contains the required alignment of the section. Must be a power of two.
    , sh32EntSize   :: Word32            -- ^ Size of entries if section has a table.
    } deriving (Eq, Show)

getElfSection32 :: ElfData -> Get ElfSection32
getElfSection32 d = ElfSection32 <$> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d

instance Binary (Be ElfSection32) where
    put = undefined
    get = Be <$> getElfSection32 ELFDATA2MSB

instance Binary (Le ElfSection32) where
    put = undefined
    get = Le <$> getElfSection32 ELFDATA2LSB

-- data ElfSection = ElfSection
--     { elfSectionName      :: String            -- ^ Identifies the name of the section.
--     , elfSectionType      :: ElfSectionType    -- ^ Identifies the type of the section.
--     , elfSectionFlagsW    :: Word64            -- ^ Identifies the attributes of the section.
--     , elfSectionAddr      :: Word64            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
--     , elfSectionSize      :: Word64            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
--     , elfSectionLink      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
--     , elfSectionInfo      :: Word32            -- ^ Contains extra information for the index, depending on type.
--     , elfSectionAddrAlign :: Word64            -- ^ Contains the required alignment of the section. Must be a power of two.
--     , elfSectionEntSize   :: Word64            -- ^ Size of entries if section has a table.
--     , elfSectionData      :: B.ByteString      -- ^ The raw data for the section.
--     } deriving (Eq, Show)

elfMagic :: B.ByteString
elfMagic = B.pack [0x7f, 0x45, 0x4c, 0x46] -- "\DELELF"

elfSupportedVersion :: Word8
elfSupportedVersion = 1

splitBits :: (Num w, FiniteBits w) => w -> [w]
splitBits w = map (shiftL 1) $ filter (testBit w) $ map (subtract 1) [ 1 .. (finiteBitSize w) ]

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

getEndian :: (Binary (Le a), Binary (Be a)) => ElfData -> Get a
getEndian ELFDATA2LSB = fromLe <$> get
getEndian ELFDATA2MSB = fromBe <$> get

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

-- -- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects have their
-- -- fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
-- parseElf :: B.ByteString -> Elf
-- parseElf b =
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

data ElfSegment64 = ElfSegment64
    { p64Type     :: ElfSegmentType   -- ^ Segment type
    , p64Flags    :: Word32           -- ^ Segment flags
    , p64Offset   :: Word64
    , p64VirtAddr :: Word64           -- ^ Virtual address for the segment
    , p64PhysAddr :: Word64           -- ^ Physical address for the segment
    , p64FileSize :: Word64
    , p64MemSize  :: Word64           -- ^ Size in memory  (may be larger then the segment's data)
    , p64Align    :: Word64           -- ^ Segment alignment
    } deriving (Eq,Show)

getElfSegment64 :: ElfData -> Get ElfSegment64
getElfSegment64 d = ElfSegment64 <$> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d

instance Binary (Be ElfSegment64) where
    put = undefined
    get = Be <$> getElfSegment64 ELFDATA2MSB

instance Binary (Le ElfSegment64) where
    put = undefined
    get = Le <$> getElfSegment64 ELFDATA2LSB

data ElfSegment32 = ElfSegment32
    { p32Type     :: ElfSegmentType   -- ^ Segment type
    , p32Offset   :: Word32
    , p32VirtAddr :: Word32           -- ^ Virtual address for the segment
    , p32PhysAddr :: Word32           -- ^ Physical address for the segment
    , p32FileSize :: Word32
    , p32MemSize  :: Word32           -- ^ Size in memory  (may be larger then the segment's data)
    , p32Flags    :: Word32           -- ^ Segment flags
    , p32Align    :: Word32           -- ^ Segment alignment
    } deriving (Eq,Show)

getElfSegment32 :: ElfData -> Get ElfSegment32
getElfSegment32 d = ElfSegment32 <$> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d
                                 <*> getEndian d

instance Binary (Be ElfSegment32) where
    put = undefined
    get = Be <$> getElfSegment32 ELFDATA2MSB

instance Binary (Le ElfSegment32) where
    put = undefined
    get = Le <$> getElfSegment32 ELFDATA2LSB

-- data ElfSegment = ElfSegment
--   { elfSegmentType      :: ElfSegmentType   -- ^ Segment type
--   , elfSegmentFlagsW    :: Word32           -- ^ Segment flags
--   , elfSegmentVirtAddr  :: Word64           -- ^ Virtual address for the segment
--   , elfSegmentPhysAddr  :: Word64           -- ^ Physical address for the segment
--   , elfSegmentAlign     :: Word64           -- ^ Segment alignment
--   , elfSegmentData      :: B.ByteString     -- ^ Data for the segment
--   , elfSegmentMemSize   :: Word64           -- ^ Size in memory  (may be larger then the segment's data)
--   } deriving (Eq,Show)

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
-- 
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
    , steEnclosingSection :: Maybe ElfSection -- ^ Section from steIndex
    , steType             :: ElfSymbolType
    , steBind             :: ElfSymbolBinding
    , steOther            :: Word8
    , steIndex            :: ElfSectionIndex  -- ^ Section in which the def is held
    , steValue            :: Word64
    , steSize             :: Word64
    } -- deriving (Eq, Show)

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
findSymbolDefinition :: ElfSymbolTableEntry -> Maybe B.ByteString
findSymbolDefinition e = steEnclosingSection e >>= \enclosingSection ->
    let enclosingData = elfSectionData enclosingSection
        start = (fromIntegral (steValue e)) - (fromIntegral (elfSectionAddr enclosingSection))
        len = fromIntegral (steSize e)
        def = (B.take len . B.drop start) enclosingData
    in if B.null def then Nothing else Just def

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
        sec = sectionByIndex e sTlbIdx
    return $ EST (nameIdx,name) sec typ bind other sTlbIdx value size
  getSymbolTableEntry64 = do
    nameIdx <- liftM fromIntegral (getWord32 er)
    info <- getWord8
    other <- getWord8
    sTlbIdx <- liftM (toEnum . fromIntegral) (getWord16 er)
    symVal <- getWord64 er
    size <- getWord64 er
    let name = stringByIndex nameIdx strs
        (typ,bind) = infoToTypeAndBind info
        sec = sectionByIndex e sTlbIdx
    return $ EST (nameIdx,name) sec typ bind other sTlbIdx symVal size

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
