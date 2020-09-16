{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTSyntax #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeFamilyDependencies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

{-# OPTIONS_GHC -Wno-unused-top-binds #-}

-- | Data.Elf is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf
    ( module Data.Elf.Generated
    , ElfPart (..)
    , Elf (..)
    ) where

import Data.Elf.Generated
import Data.Elf.Headers

import Data.ByteString.Lazy as BSL
import Data.Singletons
import Data.Singletons.Sigma
import Data.Word
import Numeric.Interval as I

data ElfPart (c :: ElfClass)
    = ElfHeader
        { ehHeader :: HeaderXX c
        }
    | ElfSection
        { esHeader :: SectionXX c
        , esN      :: Word32
        }
    | ElfSegment
        { epHeader :: SegmentXX c
        , epData   :: [ElfPart c]
        }
    | SectionTable
        { estInterval :: Interval Word64
        }
    | SegmentTable
        { espInterval :: Interval Word64
        }

-- headerSize' :: forall (a :: ElfClass) . Sing a -> Word16
-- headerSize' :: Sing a -> Word16
-- headerSize' = headerSize . fromSing

-- headerSize' :: forall (a :: ElfClass) . Sing a -> Word64
-- headerSize' :: Sing a -> Word64
-- headerSize' = undefined

-- elfPartInterval :: SingI a => ElfPart a -> Interval Word64
-- elfPartInterval ElfHeader{..} = 0 ... (withSing headerSize')
-- elfPartInterval _ = undefined

newtype Elf c = Elf [ElfPart c]

parseElf' :: SingI a => HeaderXX a -> [SectionXX a] -> [SegmentXX a] -> BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf' hdr ss ps bs = undefined

parseElf :: BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf bs = do
    classS :&: HeadersXX (hdr, ss, ps) <- parseHeaders bs
    withSingI classS $ parseElf' hdr ss ps bs
