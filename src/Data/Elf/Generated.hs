{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TemplateHaskell #-}

module Data.Elf.Generated where

import Data.Binary
import Data.Binary.Put
import Data.Binary.Get

import Data.Elf.TH

newtype Be a = Be { fromBe :: a }
newtype Le a = Le { fromLe :: a }

$(mkDeclarations BaseWord8 "ElfOSABI" "ELFOSABI" "ELFOSABI_EXT"
    [ ("_SYSV",       0  ) -- No extensions or unspecified
    , ("_HPUX",       1  ) -- Hewlett-Packard HP-UX
    , ("_NETBSD",     2  ) -- NetBSD
    , ("_LINUX",      3  ) -- Linux
    , ("_SOLARIS",    6  ) -- Sun Solaris
    , ("_AIX",        7  ) -- AIX
    , ("_IRIX",       8  ) -- IRIX
    , ("_FREEBSD",    9  ) -- FreeBSD
    , ("_TRU64",      10 ) -- Compaq TRU64 UNIX
    , ("_MODESTO",    11 ) -- Novell Modesto
    , ("_OPENBSD",    12 ) -- Open BSD
    , ("_OPENVMS",    13 ) -- Open VMS
    , ("_NSK",        14 ) -- Hewlett-Packard Non-Stop Kernel
    , ("_AROS",       15 ) -- Amiga Research OS
    , ("_ARM",        97 ) -- ARM
    , ("_STANDALONE", 255) -- Standalone (embedded) application
    ])

$(mkDeclarations BaseWord16 "ElfType" "ET" "ET_EXT"
    [ ("_NONE", 0) -- Unspecified type
    , ("_REL",  1) -- Relocatable object file
    , ("_EXEC", 2) -- Executable object file
    , ("_DYN",  3) -- Shared object file
    , ("_CORE", 4) -- Core dump object file
    ])
