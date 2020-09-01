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
import Data.ByteString.Lazy as BS
import Data.ByteString.Lazy.Char8 as BSC
import Data.Foldable as F
import Data.Functor.Identity
import Data.Int
import Data.Singletons
import Data.Singletons.Sigma
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
        takeLen off len bs = BS.take len $ BS.drop off bs
        bsSections = takeLen (wxxToIntegralS classS hShOff) (fromIntegral hShEntSize * fromIntegral hShNum) bs
        bsSegments = takeLen (wxxToIntegralS classS hPhOff) (fromIntegral hPhEntSize * fromIntegral hPhNum) bs

    (off, s :: [SectionXX a]) <- withSingI classS $ case hData of
        ELFDATA2LSB -> second (fmap fromLe . fromBList) <$> (decodeOrFailAssertion bsSections)
        ELFDATA2MSB -> second (fmap fromBe . fromBList) <$> (decodeOrFailAssertion bsSections)

    assertEqual "Not all section table could be parsed" (BS.length bsSections) off
    let
        encoded = withSingI classS $ case hData of
            ELFDATA2LSB -> encode $ BList $ Le <$> s
            ELFDATA2MSB -> encode $ BList $ Be <$> s
    assertEqual "Section table round trip does not work" bsSections encoded

    (offp, p :: [SegmentXX a]) <- withSingI classS $ case hData of
        ELFDATA2LSB -> second (fmap fromLe . fromBList) <$> (decodeOrFailAssertion bsSegments)
        ELFDATA2MSB -> second (fmap fromBe . fromBList) <$> (decodeOrFailAssertion bsSegments)

    assertEqual "Not all ssgment table could be parsed" (BS.length bsSegments) offp
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
    assertEqual "Header round trip does not work" (BS.take off bs) (encode elfh)

    mkTest'' classS hxx bs

mkTest :: FilePath -> TestTree
mkTest p = testCase p $ withBinaryFile p ReadMode (BS.hGetContents >=> mkTest')

main :: IO ()
main = do

    binDir <- getBinDir
    elfs <- traverseDir workDir isElf

    --let
    --    mkTestDump :: FilePath -> TestTree
    --    mkTestDump p = goldenVsFile
    --        "dump"
    --        g
    --        o
    --        (runExecWithStdoutFile
    --            (binDir </> "hobjdump")
    --            [p]
    --            o)
    --        where
    --            o = replaceExtension p ".out"
    --            g = replaceExtension p ".golden"

    --    mkTestLayout :: FilePath -> TestTree
    --    mkTestLayout p = goldenVsFile
    --        "layout"
    --        g
    --        o
    --        (runExecWithStdoutFile
    --            (binDir </> "hobjlayout")
    --            [p]
    --            o)
    --        where
    --            o = replaceExtension p ".layout.out"
    --            g = replaceExtension p ".layout.golden"

    --    mkTest :: FilePath -> TestTree
    --    mkTest p = testGroup p [mkTestDump p, mkTestLayout p]

    defaultMain $ testGroup "elfs" (mkTest <$> elfs)
