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
    , ElfSegment (..)
    , Elf (..)
    ) where

import Data.Elf.Generated
import Data.Elf.Headers

import Data.ByteString.Lazy  as BSL
import Data.Singletons
import Data.Singletons.Sigma

data ElfPart (c :: ElfClass)
    = Section
        { hShOff      :: Word
        , hFlags      :: Word
        , hPhEntSize  :: Word
        , hPhNum      :: Word
        , hShEntSize  :: Word
        , hShNum      :: Word
        , hShStrNdx   :: Word
        }
    | ElfHeader
    | SectionTable
    | SegmentTable

data ElfSegment (c :: ElfClass)
    = ElfSegment

-- It's just a list with two types of nodes
data Elf (c :: ElfClass)
    = ElfDataNull
    | ElfDataSection (ElfPart c)    (Elf c)
    | ElfDataSegment (ElfSegment c) (Elf c)

parseElf :: BSL.ByteString -> Either String (Sigma ElfClass (TyCon1 Elf))
parseElf = undefined
