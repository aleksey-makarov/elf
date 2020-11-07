{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}

module Main (main) where

-- import Paths_elf
import Prelude as P

import Control.Arrow
import Control.Monad
import Control.Monad.Catch
import Data.Binary
import qualified Data.ByteString as BS
import Data.ByteString.Lazy as BSL
-- import Data.ByteString.Lazy.Char8 as BSC
import Data.Foldable as F
-- import Data.Functor.Identity
import Data.Int
-- import Data.List as L
import Data.Monoid
import Data.Singletons
import Data.Singletons.Sigma
import Data.Text.Prettyprint.Doc as D
import Data.Text.Prettyprint.Doc.Render.Text
import System.Directory
import System.FilePath
import System.IO as IO
-- import System.Process.Typed
import Test.Tasty
import Test.Tasty.Golden
import Test.Tasty.HUnit

import Data.Elf
import Data.Elf.Headers
import Data.Elf.Doc

-- runExecWithStdoutFile :: FilePath -> [String] -> FilePath -> IO ()
-- runExecWithStdoutFile execFilePath args stdoutPath =
--     withBinaryFile stdoutPath WriteMode (\ oh -> do
--         let cfg = setStdout (useHandleClose oh) $ proc execFilePath args
--         runProcess_ cfg
--     )

partitionM :: Monad m => (a -> m Bool) -> [a] -> m ([a], [a])
partitionM p l = foldlM f ([], []) l
    where
        f (ts, fs) x = do
            b <- p x
            return $ if b then (x:ts, fs) else (ts, x:fs)

traverseDir :: FilePath -> (FilePath -> IO Bool) -> IO [FilePath]
traverseDir root ok = go root
    where
        go :: FilePath -> IO [FilePath]
        go dir = do
            paths <- P.map (dir </>) <$> listDirectory dir
            (dirPaths, filePaths) <- partitionM doesDirectoryExist paths
            oks <- filterM ok filePaths
            (oks ++) <$> (F.concat <$> (sequence $ P.map go dirPaths))

isElf :: FilePath -> IO Bool
isElf p = if takeExtension p == ".bad" then return False else (elfMagic ==) . decode <$> BSL.readFile p

decodeOrFailAssertion :: Binary a => ByteString -> IO (Int64, a)
decodeOrFailAssertion bs = case decodeOrFail bs of
    Left (_, off, err) -> assertFailure (err ++ " @" ++ show off)
    Right (_, off, a) -> return (off, a)

mkTest'' :: forall (a :: ElfClass) . Sing a -> HeaderXX a -> ByteString -> Assertion
mkTest'' classS HeaderXX{..} bs = do

    let
        takeLen off len = BSL.take len $ BSL.drop off bs
        bsSections = takeLen (wxxToIntegralS classS hShOff) (fromIntegral hShEntSize * fromIntegral hShNum)
        bsSegments = takeLen (wxxToIntegralS classS hPhOff) (fromIntegral hPhEntSize * fromIntegral hPhNum)

    (off, s :: [SectionXX a]) <- withSingI classS $ case hData of
        ELFDATA2LSB -> second (fmap fromLe . fromBList) <$> (decodeOrFailAssertion bsSections)
        ELFDATA2MSB -> second (fmap fromBe . fromBList) <$> (decodeOrFailAssertion bsSections)

    assertEqual "Not all section table could be parsed" (BSL.length bsSections) off
    let
        encoded = withSingI classS $ case hData of
            ELFDATA2LSB -> encode $ BList $ Le <$> s
            ELFDATA2MSB -> encode $ BList $ Be <$> s
    assertEqual "Section table round trip does not work" bsSections encoded

    (offp, p :: [SegmentXX a]) <- withSingI classS $ case hData of
        ELFDATA2LSB -> second (fmap fromLe . fromBList) <$> (decodeOrFailAssertion bsSegments)
        ELFDATA2MSB -> second (fmap fromBe . fromBList) <$> (decodeOrFailAssertion bsSegments)

    assertEqual "Not all ssgment table could be parsed" (BSL.length bsSegments) offp
    let
        encodedp = withSingI classS $ case hData of
            ELFDATA2LSB -> encode $ BList $ Le <$> p
            ELFDATA2MSB -> encode $ BList $ Be <$> p
    assertEqual "Segment table round trip does not work" bsSegments encodedp

    -- assertFailure "Oh no no no"
    return ()

mkTest' :: ByteString -> Assertion
mkTest' bs = do
    (off, elfh@(classS :&: hxx) :: Header) <- decodeOrFailAssertion bs
    assertBool "Incorrect header size" ((headerSize ELFCLASS32 == fromIntegral off) || (headerSize ELFCLASS64 == fromIntegral off))
    assertEqual "Header round trip does not work" (BSL.take off bs) (encode elfh)

    mkTest'' classS hxx bs

mkTest :: FilePath -> TestTree
mkTest p = testCase p $ withBinaryFile p ReadMode (BSL.hGetContents >=> mkTest')

mkGoldenTest :: String -> (FilePath -> IO (Doc ())) -> FilePath -> TestTree
mkGoldenTest name formatFunction file = goldenVsFile file g o mkGoldenTestOutput
    where

        newBase = "tests" </> file <.> name

        o = newBase <.> "out"
        g = newBase <.> "golden"

        mkGoldenTestOutput :: IO ()
        mkGoldenTestOutput = do
            doc <- formatFunction file
            withFile o WriteMode (\ h -> hPutDoc h doc)

sectionParseSymbolTable  :: (SingI a, MonadThrow m) => ElfData -> BSL.ByteString -> SectionXX a -> m (SectionXX a, [SymbolTableEntryXX a])
sectionParseSymbolTable d bs s = (s, ) <$> if sectionIsSymbolTable s then parseListA d $ getSectionData bs s else return []

findHeader :: SingI a => [RBuilder a] -> Maybe (HeaderXX a)
findHeader rbs = getFirst $ foldMap f rbs
    where
        f RBuilderSegment{..} = First $ findHeader erbpData
        f RBuilderHeader{ erbhHeader = h@HeaderXX{..}, ..} = First $ Just h
        f _ = First Nothing

findSection :: SingI a => Word16 -> [RBuilder a] -> Maybe (SectionXX a)
findSection n rbs = findSection' rbs
    where
        findSection' rbs' = getFirst $ foldMap f rbs'
        f RBuilderSegment{..} = First $ findSection' erbpData
        f RBuilderSection{..} = if n == erbsN then First $ Just erbsHeader else First Nothing
        f _ = First Nothing

findStringSection :: SingI a => [RBuilder a] -> Maybe (SectionXX a)
findStringSection rbs = do
    HeaderXX{..} <- findHeader rbs
    findSection hShStrNdx rbs

printRBuilderFile :: FilePath -> IO (Doc ())
printRBuilderFile path = do
    bs <- fromStrict <$> BS.readFile path
    case parseHeaders bs of
        Left err -> assertFailure $ show err
        Right (classS :&: HeadersXX (hdr@HeaderXX{..}, ss, ps)) -> withSingI classS do
            rbs <- parseRBuilder bs hdr ss ps
            let
                stringSectionData = getSectionData bs <$> findStringSection rbs
            case stringSectionData of
                Nothing -> assertFailure $ "no string table"
                Just st ->
                    let
                        getString' n = getString st $ fromIntegral n
                    in
                        return $ printRBuilder getString' rbs

printHeadersFile :: FilePath -> IO (Doc ())
printHeadersFile path = do
    bs <- fromStrict <$> BS.readFile path
    case parseHeaders bs of
        Left err -> assertFailure $ show err
        Right (classS :&: HeadersXX (hdr@HeaderXX{..}, ss, ps)) -> withSingI classS do
            case mapM (sectionParseSymbolTable hData bs) ss of
                Left err -> assertFailure $ show err
                Right sts -> return $ printHeaders hdr sts ps

printElfFile :: FilePath -> IO (Doc ())
printElfFile path = do
    bs <- fromStrict <$> BS.readFile path
    case parseElf bs of
        Left err -> assertFailure $ show err
        Right e -> return $ printElf e

main :: IO ()
main = do

    -- binDir <- getBinDir
    elfs <- traverseDir "testdata" isElf

    defaultMain $ testGroup "elf" [ testGroup "headers round trip" (mkTest <$> elfs)
                                  , testGroup "headers golden" (mkGoldenTest "header" printHeadersFile <$> elfs)
                                  , testGroup "rbuilder golden" (mkGoldenTest "rbuilder" printRBuilderFile <$> elfs)
                                  , testGroup "elf golden" (mkGoldenTest "elf" printElfFile <$> elfs)
                                  ]
