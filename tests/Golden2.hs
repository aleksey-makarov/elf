{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE DataKinds #-}

module Main (main) where

import Paths_elf
import Prelude as P

import Control.Arrow
import Control.Monad
import Data.Binary
import qualified Data.ByteString as BS
import Data.ByteString.Lazy as BSL
import Data.ByteString.Lazy.Char8 as BSC
import Data.Foldable as F
import Data.Functor.Identity
import Data.Int
import Data.Singletons
import Data.Singletons.Sigma
import Data.Text.Prettyprint.Doc as D
import Data.Text.Prettyprint.Doc.Render.Text
import System.Directory
import System.FilePath
import System.IO as IO
import System.Process.Typed
import Test.Tasty
import Test.Tasty.Golden
import Test.Tasty.HUnit

import Data.Elf2

workDir :: FilePath
workDir = "testdata"

runExecWithStdoutFile :: FilePath -> [String] -> FilePath -> IO ()
runExecWithStdoutFile execFilePath args stdoutPath =
    withBinaryFile stdoutPath WriteMode (\ oh -> do
        let cfg = setStdout (useHandleClose oh) $ proc execFilePath args
        runProcess_ cfg
    )

partitionM :: Monad m => (a -> m Bool) -> [a] -> m ([a], [a])
partitionM p l = foldlM f ([], []) l
    where
        f (ts, fs) x = do
            b <- p x
            return $ if b then (x:ts, fs) else (ts, x:fs)

traverseDir :: FilePath -> (FilePath -> Bool) -> IO [FilePath]
traverseDir root ok = go root
    where
        go :: FilePath -> IO [FilePath]
        go dir = do
            paths <- P.map (dir </>) <$> listDirectory dir
            (dirPaths, filePaths) <- partitionM doesDirectoryExist paths
            let
                oks = P.filter ok filePaths
            (oks ++) <$> (F.concat <$> (sequence $ P.map go dirPaths))

isElf :: FilePath -> Bool
isElf p = takeExtension p == ".elf"

decodeOrFailAssertion :: Binary a => ByteString -> IO (Int64, a)
decodeOrFailAssertion bs = case decodeOrFail bs of
    Left (_, off, err) -> assertFailure (err ++ " @" ++ show off)
    Right (_, off, a) -> return (off, a)

mkTest'' :: forall (a :: ElfClass) . Sing a -> HeaderXX a -> ByteString -> Assertion
mkTest'' classS hxx@HeaderXX{..} bs = do

    let
        takeLen off len bs = BSL.take len $ BSL.drop off bs
        bsSections = takeLen (wxxToIntegralS classS hShOff) (fromIntegral hShEntSize * fromIntegral hShNum) bs
        bsSegments = takeLen (wxxToIntegralS classS hPhOff) (fromIntegral hPhEntSize * fromIntegral hPhNum) bs

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
        o = replaceExtension file "." ++ name ++ ".out"
        g = replaceExtension file "." ++ name ++ ".golden"

        mkGoldenTestOutput :: IO ()
        mkGoldenTestOutput = do
            doc <- formatFunction file
            withFile o WriteMode (\ h -> hPutDoc h doc)

-- FIXME: how to get rid of this? (use some combinators for Sigma)
newtype ElfHeadersXX a = ElfHeadersXXC (HeaderXX a, SectionXX a, SegmentXX a)
-- type ElfHeadersXX a = (HeaderXX a, SectionXX a, SegmentXX a)

parseHeaders :: ByteString -> Sigma ElfClass (TyCon1 ElfHeadersXX)
parseHeaders = undefined

printHeaders' :: Sigma ElfClass (TyCon1 ElfHeadersXX) -> Doc ()
printHeaders' (classS :&: ElfHeadersXXC (hdr, ss, ps)) = undefined

printHeaders :: FilePath -> IO (Doc ())
printHeaders path = do
    bs <- fromStrict <$> BS.readFile path
    return $ printHeaders' $ parseHeaders bs

main :: IO ()
main = do

    binDir <- getBinDir
    elfs <- traverseDir workDir isElf

    defaultMain $ testGroup "elf" [ testGroup "headers round trip" (mkTest <$> elfs)
                                  , testGroup "headers golden" (mkGoldenTest "header" printHeaders <$> elfs)
                                  ]
