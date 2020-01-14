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

                , splitBits

                , ElfSymbolTableEntry(..)
                , ElfSymbolBinding(..)
                , ElfSectionIndex(..)
                , elfParseSymbolTable

{-
                , findSymbolDefinition
                , findSectionByName
-}
                , module Data.Elf.Generated) where


import Data.Binary
import Data.Binary.Get as G
import Data.Bits
import Control.Monad
import qualified Data.ByteString               as B
import qualified Data.ByteString.Lazy          as L
import qualified Data.ByteString.Lazy.Internal as L
import qualified Data.ByteString.Char8         as C
import Data.Proxy

-- https://stackoverflow.com/questions/10672981/export-template-haskell-generated-definitions
import Data.Elf.Generated

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
        { e64Entry    :: Word64
        , e64Segments :: [ElfSegmentXX c]
        , e64Sections :: [ElfSectionXX c]
        } -> ElfXX 'ELFCLASS64
    Elf32 ::
        { e32Entry    :: Word32
        , e32Segments :: [ElfSegmentXX c]
        , e32Sections :: [ElfSectionXX c]
        } -> ElfXX 'ELFCLASS32

-- FIXME: fix this crap
class ElfXXTools (c :: ElfClass) w | c -> w where
    mkElfXX :: Proxy c -> w -> [ElfSegmentXX c] -> [ElfSectionXX c] -> ElfXX c

instance ElfXXTools 'ELFCLASS32 Word32 where
    mkElfXX _ = Elf32

instance ElfXXTools 'ELFCLASS64 Word64 where
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
elfEntry (Elf { elfXX = Elf64 {..} }) = e64Entry
elfEntry (Elf { elfXX = Elf32 {..} }) = fromIntegral e32Entry

elfSections :: Elf -> [ElfSection]
elfSections e@(Elf { elfXX = Elf64 {..} }) = fmap (ElfSection e) e64Sections
elfSections e@(Elf { elfXX = Elf32 {..} }) = fmap (ElfSection e) e32Sections

elfSegments :: Elf -> [ElfSegment]
elfSegments e@(Elf { elfXX = Elf64 {..} }) = fmap (ElfSegment e) e64Segments
elfSegments e@(Elf { elfXX = Elf32 {..} }) = fmap (ElfSegment e) e32Segments

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
elfSectionName (ElfSection elf (ElfSection64 {..} )) = maybe "" id $ getString elf s64Name
elfSectionName (ElfSection elf (ElfSection32 {..} )) = maybe "" id $ getString elf s32Name

elfSectionType :: ElfSection -> ElfSectionType -- ^ Identifies the name of the section.
elfSectionType (ElfSection _ (ElfSection64 {..} )) = s64Type
elfSectionType (ElfSection _ (ElfSection32 {..} )) = s32Type

elfSectionFlags :: ElfSection -> ElfSectionFlag -- ^ Identifies the attributes of the section.
elfSectionFlags (ElfSection _ (ElfSection64 {..} )) = ElfSectionFlag s64Flags
elfSectionFlags (ElfSection _ (ElfSection32 {..} )) = ElfSectionFlag $ fromIntegral s32Flags

elfSectionAddr :: ElfSection -> Word64 -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
elfSectionAddr (ElfSection _ (ElfSection64 {..} )) = s64Addr
elfSectionAddr (ElfSection _ (ElfSection32 {..} )) = fromIntegral s32Addr

elfSectionSize :: ElfSection -> Word64 -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
elfSectionSize (ElfSection _ (ElfSection64 {..} )) = s64Size
elfSectionSize (ElfSection _ (ElfSection32 {..} )) = fromIntegral s32Size

elfSectionLink :: ElfSection -> Word32 -- ^ Contains a section index of an associated section, depending on section type.
elfSectionLink (ElfSection _ (ElfSection64 {..} )) = s64Link
elfSectionLink (ElfSection _ (ElfSection32 {..} )) = s32Link

elfSectionInfo :: ElfSection -> Word32 -- ^ Contains extra information for the index, depending on type.
elfSectionInfo (ElfSection _ (ElfSection64 {..} )) = s64Info
elfSectionInfo (ElfSection _ (ElfSection32 {..} )) = s32Info

elfSectionAddrAlign :: ElfSection -> Word64 -- ^ Contains the required alignment of the section. Must be a power of two.
elfSectionAddrAlign (ElfSection _ (ElfSection64 {..} )) = s64AddrAlign
elfSectionAddrAlign (ElfSection _ (ElfSection32 {..} )) = fromIntegral s32AddrAlign

elfSectionEntSize :: ElfSection -> Word64 -- ^ Size of entries if section has a table.
elfSectionEntSize (ElfSection _ (ElfSection64 {..} )) = s64EntSize
elfSectionEntSize (ElfSection _ (ElfSection32 {..} )) = fromIntegral s32EntSize

-- FIXME: this can fail on 32 bit machine working with 64 bit elfs
getData :: Elf -> Int -> Int -> B.ByteString
getData (Elf {..}) o s = B.take s $ B.drop o elfContent

elfSectionData :: ElfSection -> B.ByteString -- ^ The raw data for the section.
elfSectionData (ElfSection elf (ElfSection64 {..})) = getData elf (fromIntegral s64Offset) (fromIntegral s64Size)
elfSectionData (ElfSection elf (ElfSection32 {..})) = getData elf (fromIntegral s32Offset) (fromIntegral s32Size)

elfSegmentType :: ElfSegment -> ElfSegmentType -- ^ Segment type
elfSegmentType (ElfSegment _ (ElfSegment64 {..} )) = p64Type
elfSegmentType (ElfSegment _ (ElfSegment32 {..} )) = p32Type

elfSegmentFlags :: ElfSegment -> ElfSegmentFlag -- ^ Segment flags
elfSegmentFlags (ElfSegment _ (ElfSegment64 {..} )) = ElfSegmentFlag p64Flags
elfSegmentFlags (ElfSegment _ (ElfSegment32 {..} )) = ElfSegmentFlag p32Flags

elfSegmentVirtAddr :: ElfSegment -> Word64 -- ^ Virtual address for the segment
elfSegmentVirtAddr (ElfSegment _ (ElfSegment64 {..} )) = p64VirtAddr
elfSegmentVirtAddr (ElfSegment _ (ElfSegment32 {..} )) = fromIntegral p32VirtAddr

elfSegmentPhysAddr :: ElfSegment -> Word64 -- ^ Physical address for the segment
elfSegmentPhysAddr (ElfSegment _ (ElfSegment64 {..} )) = p64PhysAddr
elfSegmentPhysAddr (ElfSegment _ (ElfSegment32 {..} )) = fromIntegral p32PhysAddr

elfSegmentAlign :: ElfSegment -> Word64 -- ^ Segment alignment
elfSegmentAlign (ElfSegment _ (ElfSegment64 {..} )) = p64Align
elfSegmentAlign (ElfSegment _ (ElfSegment32 {..} )) = fromIntegral p32Align

elfSegmentData :: ElfSegment -> B.ByteString -- ^ Data for the segment
elfSegmentData (ElfSegment elf (ElfSegment64 {..})) = getData elf (fromIntegral p64Offset) (fromIntegral p64PileSize)
elfSegmentData (ElfSegment elf (ElfSegment32 {..})) = getData elf (fromIntegral p32Offset) (fromIntegral p32FileSize)

elfSegmentMemSize :: ElfSegment -> Word64 -- ^ Size in memory  (may be larger then the segment's data)
elfSegmentMemSize (ElfSegment _ (ElfSegment64 {..} )) = p64MemSize
elfSegmentMemSize (ElfSegment _ (ElfSegment32 {..} )) = fromIntegral p32MemSize

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

    -- FIXME: fix this later
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

data ElfReader = ElfReader
    { getWord16 :: Get Word16
    , getWord32 :: Get Word32
    , getWord64 :: Get Word64
    }

elfReader :: ElfData -> ElfReader
elfReader ELFDATA2LSB = ElfReader { getWord16 = getWord16le, getWord32 = getWord32le, getWord64 = getWord64le }
elfReader ELFDATA2MSB = ElfReader { getWord16 = getWord16be, getWord32 = getWord32be, getWord64 = getWord64be }

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

elfParseSymbolTable :: ElfSection -> [ElfSymbolTableEntry]
elfParseSymbolTable s@(ElfSection elf _) =
    if elfSectionType s `elem` [SHT_SYMTAB, SHT_DYNSYM]
        then getSymbolTableEntries elf s
        else []

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

infoToTypeAndBind :: Word8 -> (ElfSymbolType,ElfSymbolBinding)
infoToTypeAndBind i =
    let t = fromIntegral $ i .&. 0x0F
        b = fromIntegral $ (i .&. 0xF0) `shiftR` 4
    in (ElfSymbolType t, toEnum b)

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

-- -- | Given a section name, extract the ElfSection.
-- findSectionByName :: String -> Elf -> Maybe ElfSection
-- findSectionByName name = listToMaybe . filter ((==) name . elfSectionName) . elfSections

-- Get a string from a strtab ByteString.
stringByIndex :: Integral n => n -> B.ByteString -> Maybe B.ByteString
stringByIndex n strtab =
    let str = (B.takeWhile (/=0) . B.drop (fromIntegral n)) strtab
    in if B.length str == 0 then Nothing else Just str
