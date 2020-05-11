{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Main (main) where

import Paths_elf

import Data.Foldable
import System.Directory
import System.FilePath
import System.IO
import System.Process.Typed
import Test.Tasty
import Test.Tasty.Golden

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
            paths <- map (dir </>) <$> listDirectory dir
            (dirPaths, filePaths) <- partitionM doesDirectoryExist paths
            let
                oks = filter ok filePaths
            (oks ++) <$> (concat <$> (sequence $ map go dirPaths))

isElf :: FilePath -> Bool
isElf p = takeExtension p == ".elf"

main :: IO ()
main = do

    let
        dir = "testdata"

    binDir <- getBinDir
    elfs <- traverseDir dir isElf

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

    defaultMain $ testGroup "Golden" (mkTest <$> elfs)
