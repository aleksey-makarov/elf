{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Main (main) where

import Paths_elf
import Prelude as P

import Data.Binary
import Data.ByteString.Lazy as BSL
import Data.Elf
import Data.Foldable as F
import System.Directory
import System.FilePath
import System.IO
import System.Process.Typed
import Test.Tasty
import Test.Tasty.Golden
import Test.Tasty.HUnit

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

syscallTest :: TestTree
syscallTest = testCase "syscall" $ encodeFile (workDir </> "syscall") $ mkElf sectionList
    where
        sectionList :: ElfSectionList
        sectionList   = S BSL.empty
                    :++ p1
                    :++ S BSL.empty
                    :++ S BSL.empty
                    :++ PEnd p1
                    :++ p2
                    :++ S BSL.empty
                    :++ PEnd p2
        p1 = P
        p2 = P

main :: IO ()
main = do

    binDir <- getBinDir
    elfs <- traverseDir workDir isElf

    let
        mkTestDump :: FilePath -> TestTree
        mkTestDump p = goldenVsFile
            "dump"
            g
            o
            (runExecWithStdoutFile
                (binDir </> "hobjdump")
                [p]
                o)
            where
                o = replaceExtension p ".out"
                g = replaceExtension p ".golden"

        mkTestLayout :: FilePath -> TestTree
        mkTestLayout p = goldenVsFile
            "layout"
            g
            o
            (runExecWithStdoutFile
                (binDir </> "hobjlayout")
                [p]
                o)
            where
                o = replaceExtension p ".layout.out"
                g = replaceExtension p ".layout.golden"

        mkTest :: FilePath -> TestTree
        mkTest p = testGroup p [mkTestDump p, mkTestLayout p]

    defaultMain $ testGroup "Golden" [ testGroup "Reference" (mkTest <$> elfs)
                                     , testGroup "Generated" [ syscallTest ]
                                     ]
