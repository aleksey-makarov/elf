{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

module Main (main) where

-- import Paths_elf
import Prelude as P

import Data.Binary
import Data.ByteString.Lazy.Char8 as BSC
import Data.Elf2
-- import Data.Foldable as F
import Data.Functor.Identity
-- import System.Directory
import System.FilePath
-- import System.IO
-- import System.Process.Typed
import Test.Tasty
-- import Test.Tasty.Golden
import Test.Tasty.HUnit

workDir :: FilePath
workDir = "testdata"

syscallTest :: TestTree
syscallTest = testCase "syscall" $ encodeFile (workDir </> "syscall") elf
    where
        elf = runIdentity $ mkElf SELFCLASS64 ELFDATA2LSB ELFOSABI_LINUX 0 ET_EXEC EM_386 0 do
            mkHeader
            mkSection "section1" 1000 $ BSC.pack "section1 data"
            mkSegment do
                mkSection "section2" 1000 $ BSC.pack "section2 data"
                mkSection "section3" 1000 $ BSC.pack "section3 data"
            mkSegment $ mkSection "section4" 1000 $ BSC.pack "section4 data"
            mkSectionTable
            mkSegmentTable

main :: IO ()
main = defaultMain $ testGroup "syscall" [ syscallTest ]
