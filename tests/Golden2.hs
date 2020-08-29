{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}

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

getSectionTableByteString :: Header -> ByteString -> ByteString
getSectionTableByteString (classS :&: HeaderXX{..}) bs = BS.take (fromIntegral hShEntSize * fromIntegral hShNum) $ BS.drop (wxxToIntegralS classS hShOff) bs

getSegmentTableByteString :: Header -> ByteString -> ByteString
getSegmentTableByteString (classS :&: HeaderXX{..}) bs = BS.take (fromIntegral hPhEntSize * fromIntegral hPhNum) $ BS.drop (wxxToIntegralS classS hPhOff) bs

decodeOrFailAssertion :: Binary a => ByteString -> IO (Int64, a)
decodeOrFailAssertion bs = case decodeOrFail bs of
    Left (_, off, err) -> assertFailure (err ++ " @" ++ show off)
    Right (_, off, a) -> return (off, a)

mkTest' :: ByteString -> Assertion
mkTest' bs = do
    (off, elfh@(_ :&: HeaderXX{..})) <- decodeOrFailAssertion bs
    assertBool "Incorrect header size" ((headerSize ELFCLASS32 == fromIntegral off) || (headerSize ELFCLASS64 == fromIntegral off))
    assertEqual "Header round trip does not work" (BS.take off bs) (encode elfh)

    let
        bsSections = getSectionTableByteString elfh bs
        bsSegments = getSegmentTableByteString elfh bs

    -- x <- case hData of
    --     ELFDATA2LSB -> second (fmap fromLe . fromBList) <$> (decodeOrFailAssertion bsSections)
    --     ELFDATA2MSB -> second (fmap fromBe . fromBList) <$> (decodeOrFailAssertion bsSections)

    -- assertFailure "Oh no no no"
    return ()

mkTest :: FilePath -> TestTree
mkTest p = testCase p $ withBinaryFile p ReadMode (BS.hGetContents >=> mkTest'')

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
