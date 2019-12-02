{-# LANGUAGE FlexibleContexts #-}

-- | Data.Elf is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf ( parseElf
                , parseSymbolTables
                , findSymbolDefinition
                , findSectionByName

                , Elf(..)
                , elfVersion

                , ElfSection(..)
                , ElfSectionFlags(..)
                , ElfSegment(..)
                , ElfSegmentType(..)
                , ElfSegmentFlag(..)
                , ElfClass(..)
                , ElfData(..)

                , ElfMachine(..)
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
import qualified Data.ByteString.Internal      as B
import qualified Data.ByteString.Lazy          as L
import qualified Data.ByteString.Lazy.Internal as L

-- https://stackoverflow.com/questions/10672981/export-template-haskell-generated-definitions
import Data.Elf.Generated

data Elf = Elf
    { elfClass      :: ElfClass      -- ^ Identifies the class of the object file (32/64 bit).
    , elfData       :: ElfData       -- ^ Identifies the data encoding of the object file (endianness).
    , elfOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
    , elfABIVersion :: Word8         -- ^ Identifies the ABI version for which the object is prepared.
    , elfType       :: ElfType       -- ^ Identifies the object file type.
    , elfMachine    :: ElfMachine    -- ^ Identifies the target architecture.
    , elfEntry      :: Word64        -- ^ Virtual address of the program entry point. 0 for non-executable Elfs.
    , elfSections   :: [ElfSection]  -- ^ List of sections in the file.
    , elfSegments   :: [ElfSegment]  -- ^ List of segments in the file.
    } deriving (Eq, Show)

elfVersion :: Elf -> Int
elfVersion _ = elfSupportedVersion

data ElfSection = ElfSection
    { elfSectionName      :: String            -- ^ Identifies the name of the section.
    , elfSectionType      :: ElfSectionType    -- ^ Identifies the type of the section.
    , elfSectionFlags     :: [ElfSectionFlags] -- ^ Identifies the attributes of the section.
    , elfSectionAddr      :: Word64            -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
    , elfSectionSize      :: Word64            -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
    , elfSectionLink      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
    , elfSectionInfo      :: Word32            -- ^ Contains extra information for the index, depending on type.
    , elfSectionAddrAlign :: Word64            -- ^ Contains the required alignment of the section. Must be a power of two.
    , elfSectionEntSize   :: Word64            -- ^ Size of entries if section has a table.
    , elfSectionData      :: B.ByteString      -- ^ The raw data for the section.
    } deriving (Eq, Show)

elfMagic :: [Word8]
elfMagic = [0x7f, 0x45, 0x4c, 0x46] -- "\DELELF"

elfSupportedVersion :: Int
elfSupportedVersion = 1

verifyElfMagic :: Get ()
verifyElfMagic = do
    ei_magic <- replicateM 4 getWord8
    if ei_magic /= elfMagic
        then fail "Invalid magic number for ELF"
        else return ()

verifyElfVersion :: Get ()
verifyElfVersion = do
    ei_version <- getWord8
    if ei_version /= 1
        then fail "Invalid version number for ELF"
        else return ()

data ElfSectionFlags
    = SHF_WRITE     -- ^ Section contains writable data
    | SHF_ALLOC     -- ^ Section is allocated in memory image of program
    | SHF_EXECINSTR -- ^ Section contains executable instructions
    | SHF_EXT Int   -- ^ Processor- or environment-specific flag
    deriving (Eq, Show)

getElfSectionFlags :: Bits a => Int -> a -> [ElfSectionFlags]
getElfSectionFlags 0 _ = []
getElfSectionFlags 1 word | testBit word 0     = SHF_WRITE     : getElfSectionFlags 0 word
getElfSectionFlags 2 word | testBit word 1     = SHF_ALLOC     : getElfSectionFlags 1 word
getElfSectionFlags 3 word | testBit word 2     = SHF_EXECINSTR : getElfSectionFlags 2 word
getElfSectionFlags n word | testBit word (n-1) = SHF_EXT (n-1) : getElfSectionFlags (n-1) word
getElfSectionFlags n word = getElfSectionFlags (n-1) word

getElfSectionFlags32 :: ElfReader -> Get [ElfSectionFlags]
getElfSectionFlags64 :: ElfReader -> Get [ElfSectionFlags]
getElfSectionFlags32 = liftM (getElfSectionFlags 32) . getWord32
getElfSectionFlags64 = liftM (getElfSectionFlags 64) . getWord64

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

getElf_Shdr_OffsetSize :: ElfClass -> ElfReader -> Get (Word64, Word64)
getElf_Shdr_OffsetSize ei_class er =
    case ei_class of
        ELFCLASS32 -> do
            skip 16
            sh_offset <- liftM fromIntegral $ getWord32 er
            sh_size   <- liftM fromIntegral $ getWord32 er
            return (sh_offset, sh_size)
        ELFCLASS64 -> do
            skip 24
            sh_offset <- getWord64 er
            sh_size   <- getWord64 er
            return (sh_offset, sh_size)

getElf_Shdr :: ElfData -> ElfClass -> ElfReader -> B.ByteString -> B.ByteString -> Get ElfSection
getElf_Shdr ei_data ei_class er elf_file string_section =
    case ei_class of
        ELFCLASS32 -> do
            sh_name      <- getWord32 er
            sh_type      <- getWithEndianness ei_data
            sh_flags     <- getElfSectionFlags32 er
            sh_addr      <- getWord32 er
            sh_offset    <- getWord32 er
            sh_size      <- getWord32 er
            sh_link      <- getWord32 er
            sh_info      <- getWord32 er
            sh_addralign <- getWord32 er
            sh_entsize   <- getWord32 er
            return ElfSection
                { elfSectionName      = map B.w2c $ B.unpack $ B.takeWhile (/= 0) $ B.drop (fromIntegral sh_name) string_section
                , elfSectionType      = sh_type
                , elfSectionFlags     = sh_flags
                , elfSectionAddr      = fromIntegral sh_addr
                , elfSectionSize      = fromIntegral sh_size
                , elfSectionLink      = sh_link
                , elfSectionInfo      = sh_info
                , elfSectionAddrAlign = fromIntegral sh_addralign
                , elfSectionEntSize   = fromIntegral sh_entsize
                , elfSectionData      = B.take (fromIntegral sh_size) $ B.drop (fromIntegral sh_offset) elf_file
                }
        ELFCLASS64 -> do
            sh_name      <- getWord32 er
            sh_type      <- getWithEndianness ei_data
            sh_flags     <- getElfSectionFlags64 er
            sh_addr      <- getWord64 er
            sh_offset    <- getWord64 er
            sh_size      <- getWord64 er
            sh_link      <- getWord32 er
            sh_info      <- getWord32 er
            sh_addralign <- getWord64 er
            sh_entsize   <- getWord64 er
            return ElfSection
                { elfSectionName      = map B.w2c $ B.unpack $ B.takeWhile (/= 0) $ B.drop (fromIntegral sh_name) string_section
                , elfSectionType      = sh_type
                , elfSectionFlags     = sh_flags
                , elfSectionAddr      = sh_addr
                , elfSectionSize      = sh_size
                , elfSectionLink      = sh_link
                , elfSectionInfo      = sh_info
                , elfSectionAddrAlign = sh_addralign
                , elfSectionEntSize   = sh_entsize
                , elfSectionData      = B.take (fromIntegral sh_size) $ B.drop (fromIntegral sh_offset) elf_file
                }

data TableInfo = TableInfo { tableOffset :: Int, entrySize :: Int, entryNum :: Int }

getWithEndianness :: (Binary (Le a), Binary (Be a)) => ElfData -> Get a
getWithEndianness ELFDATA2LSB = fromLe <$> get
getWithEndianness ELFDATA2MSB = fromBe <$> get

getElf_Ehdr :: Get (Elf, TableInfo, TableInfo, Word16)
getElf_Ehdr = do
    verifyElfMagic
    ei_class    <- get
    ei_data     <- get
    verifyElfVersion
    ei_osabi    <- get
    ei_abiver   <- get
    skip 7
    er          <- return $ elfReader ei_data
    e_type      <- getWithEndianness ei_data
    e_machine   <- getWithEndianness ei_data
    _           <- getWord32 er
    case ei_class of
        ELFCLASS32 -> do
            e_entry     <- liftM fromIntegral $ getWord32 er
            e_phoff     <- getWord32 er
            e_shoff     <- getWord32 er
            _           <- getWord32 er
            _           <- getWord16 er
            e_phentsize <- getWord16 er
            e_phnum     <- getWord16 er
            e_shentsize <- getWord16 er
            e_shnum     <- getWord16 er
            e_shstrndx  <- getWord16 er
            return (Elf { elfClass      = ei_class
                        , elfData       = ei_data
                        , elfOSABI      = ei_osabi
                        , elfABIVersion = ei_abiver
                        , elfType       = e_type
                        , elfMachine    = e_machine
                        , elfEntry      = e_entry
                        , elfSections   = []
                        , elfSegments   = [] }
                   , TableInfo { tableOffset = fromIntegral e_phoff, entrySize = fromIntegral e_phentsize, entryNum = fromIntegral e_phnum }
                   , TableInfo { tableOffset = fromIntegral e_shoff, entrySize = fromIntegral e_shentsize, entryNum = fromIntegral e_shnum }
                   , e_shstrndx)
        ELFCLASS64 -> do
            e_entry     <- getWord64 er
            e_phoff     <- getWord64 er
            e_shoff     <- getWord64 er
            _           <- getWord32 er
            _           <- getWord16 er
            e_phentsize <- getWord16 er
            e_phnum     <- getWord16 er
            e_shentsize <- getWord16 er
            e_shnum     <- getWord16 er
            e_shstrndx  <- getWord16 er
            return (Elf { elfClass      = ei_class
                        , elfData       = ei_data
                        , elfOSABI      = ei_osabi
                        , elfABIVersion = ei_abiver
                        , elfType       = e_type
                        , elfMachine    = e_machine
                        , elfEntry      = e_entry
                        , elfSections   = []
                        , elfSegments   = [] }
                   , TableInfo { tableOffset = fromIntegral e_phoff, entrySize = fromIntegral e_phentsize, entryNum = fromIntegral e_phnum }
                   , TableInfo { tableOffset = fromIntegral e_shoff, entrySize = fromIntegral e_shentsize, entryNum = fromIntegral e_shnum }
                   , e_shstrndx)

data ElfReader = ElfReader
    { getWord16 :: Get Word16
    , getWord32 :: Get Word32
    , getWord64 :: Get Word64
    }

elfReader :: ElfData -> ElfReader
elfReader ELFDATA2LSB = ElfReader { getWord16 = getWord16le, getWord32 = getWord32le, getWord64 = getWord64le }
elfReader ELFDATA2MSB = ElfReader { getWord16 = getWord16be, getWord32 = getWord32be, getWord64 = getWord64be }

divide :: B.ByteString -> Int -> Int -> [B.ByteString]
divide  _ _ 0 = []
divide bs s n = let (x,y) = B.splitAt s bs in x : divide y s (n-1)

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects have their
-- fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> Elf
parseElf b =
    let ph                                             = table segTab
        sh                                             = table secTab
        (shstroff, shstrsize)                          = parseEntry getElf_Shdr_OffsetSize $ head $ drop (fromIntegral e_shstrndx) sh
        sh_str                                         = B.take (fromIntegral shstrsize) $ B.drop (fromIntegral shstroff) b
        segments                                       = map (parseEntry (\c r -> parseElfSegmentEntry c r b)) ph
        sections                                       = map (parseEntry (\c r -> getElf_Shdr (elfData e) c r b sh_str)) sh
    in e { elfSections = sections, elfSegments = segments }

  where table i                         = divide (B.drop (tableOffset i) b) (entrySize i) (entryNum i)
        parseEntry p x                  = runGet (p (elfClass e) (elfReader (elfData e))) (L.fromChunks [x])
        (e, segTab, secTab, e_shstrndx) = runGet getElf_Ehdr $ L.fromChunks [b]


data ElfSegment = ElfSegment
  { elfSegmentType      :: ElfSegmentType   -- ^ Segment type
  , elfSegmentFlags     :: [ElfSegmentFlag] -- ^ Segment flags
  , elfSegmentVirtAddr  :: Word64           -- ^ Virtual address for the segment
  , elfSegmentPhysAddr  :: Word64           -- ^ Physical address for the segment
  , elfSegmentAlign     :: Word64           -- ^ Segment alignment
  , elfSegmentData      :: B.ByteString     -- ^ Data for the segment
  , elfSegmentMemSize   :: Word64           -- ^ Size in memory  (may be larger then the segment's data)
  } deriving (Eq,Show)

-- | Segment Types.
data ElfSegmentType
  = PT_NULL         -- ^ Unused entry
  | PT_LOAD         -- ^ Loadable segment
  | PT_DYNAMIC      -- ^ Dynamic linking tables
  | PT_INTERP       -- ^ Program interpreter path name
  | PT_NOTE         -- ^ Note sectionks
  | PT_SHLIB        -- ^ Reserved
  | PT_PHDR         -- ^ Program header table
  | PT_Other Word32 -- ^ Some other type
    deriving (Eq,Show)

parseElfSegmentType :: Word32 -> ElfSegmentType
parseElfSegmentType x =
  case x of
    0 -> PT_NULL
    1 -> PT_LOAD
    2 -> PT_DYNAMIC
    3 -> PT_INTERP
    4 -> PT_NOTE
    5 -> PT_SHLIB
    6 -> PT_PHDR
    _ -> PT_Other x


parseElfSegmentEntry :: ElfClass -> ElfReader -> B.ByteString -> Get ElfSegment
parseElfSegmentEntry elf_class er elf_file = case elf_class of
  ELFCLASS64 -> do
     p_type   <- parseElfSegmentType  `fmap` getWord32 er
     p_flags  <- parseElfSegmentFlags `fmap` getWord32 er
     p_offset <- getWord64 er
     p_vaddr  <- getWord64 er
     p_paddr  <- getWord64 er
     p_filesz <- getWord64 er
     p_memsz  <- getWord64 er
     p_align  <- getWord64 er
     return ElfSegment
       { elfSegmentType     = p_type
       , elfSegmentFlags    = p_flags
       , elfSegmentVirtAddr = p_vaddr
       , elfSegmentPhysAddr = p_paddr
       , elfSegmentAlign    = p_align
       , elfSegmentData     = B.take (fromIntegral p_filesz) $ B.drop (fromIntegral p_offset) elf_file
       , elfSegmentMemSize  = p_memsz
       }

  ELFCLASS32 -> do
     p_type   <- parseElfSegmentType  `fmap` getWord32 er
     p_offset <- fromIntegral `fmap` getWord32 er
     p_vaddr  <- fromIntegral `fmap` getWord32 er
     p_paddr  <- fromIntegral `fmap` getWord32 er
     p_filesz <- fromIntegral `fmap` getWord32 er
     p_memsz  <- fromIntegral `fmap` getWord32 er
     p_flags  <- parseElfSegmentFlags `fmap` getWord32 er
     p_align  <- fromIntegral `fmap` getWord32 er
     return ElfSegment
       { elfSegmentType     = p_type
       , elfSegmentFlags    = p_flags
       , elfSegmentVirtAddr = p_vaddr
       , elfSegmentPhysAddr = p_paddr
       , elfSegmentAlign    = p_align
       , elfSegmentData     = B.take p_filesz $ B.drop p_offset elf_file
       , elfSegmentMemSize  = p_memsz
       }

data ElfSegmentFlag
  = PF_X        -- ^ Execute permission
  | PF_W        -- ^ Write permission
  | PF_R        -- ^ Read permission
  | PF_Ext Int  -- ^ Some other flag, the Int is the bit number for the flag.
    deriving (Eq,Show)

parseElfSegmentFlags :: Word32 -> [ElfSegmentFlag]
parseElfSegmentFlags word = [ cvt bit_ | bit_ <- [ 0 .. 31 ], testBit word bit_ ]
  where cvt 0 = PF_X
        cvt 1 = PF_W
        cvt 2 = PF_R
        cvt n = PF_Ext n

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
