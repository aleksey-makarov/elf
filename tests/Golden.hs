{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Main (main) where

import Paths_elf

import Control.Monad
import System.FilePath
import System.IO
import System.Process.Typed
import Test.Tasty
import Test.Tasty.Golden

runExecWithStdoutFile :: FilePath -> [String] -> FilePath -> IO ()
runExecWithStdoutFile execFilePath args stdoutPath =
    withBinaryFile stdoutPath WriteMode (\ oh -> do
        let cfg = setStdout (useHandleClose oh) $ proc execFilePath args
        void $ runProcess cfg
    )

main :: IO ()
main = do

    binDir <- getBinDir

    let
        dir = "testdata"

        mkTest :: String -> TestTree
        mkTest t = goldenVsFile
                        t
                        (dir </> t <.> "golden")
                        (dir </> t <.> "out")
                        (runExecWithStdoutFile
                            (binDir </> "hobjdump")
                            [dir </> t]
                            (dir </> t <.> "out"))

        mkTestCopy :: String -> TestTree
        mkTestCopy t = goldenVsFile
                        (t ++ ".copy")
                        (dir </> t <.> "golden")
                        (dir </> t <.> "copy" <.> "out")
                        do
                            runExecWithStdoutFile
                                (binDir </> "hobjcopy")
                                [dir </> t, dir </> t <.> "copy"]
                                "/dev/null"
                            runExecWithStdoutFile
                                (binDir </> "hobjdump")
                                [dir </> t <.> "copy"]
                                (dir </> t <.> "copy" <.> "out")

    defaultMain $ testGroup "Golden" [ mkTest "bloated"
                                     , mkTest "tiny"
                                     , mkTest "vdso"
                                     , mkTestCopy "bloated"
                                     , mkTestCopy "tiny"
                                     , mkTestCopy "vdso"
                                     ]
