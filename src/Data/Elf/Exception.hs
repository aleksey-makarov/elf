{-# LANGUAGE RecordWildCards #-}

module Data.Elf.Exception
    ( ElfException
    , elfError
    , elfError'
    , addContext
    , addContext'
    ) where

-- https://stackoverflow.com/questions/13379356/finding-the-line-number-of-a-function-in-haskell

import Control.Exception hiding (try, catch)
import Control.Monad.Catch

data ElfException = ElfException
    { s     :: String
    , ctxt  :: String
    , stack :: Maybe SomeException
    }

instance Show ElfException where
    show ElfException{..} = maybe showThis f stack
        where
            showThis = (if null s then [] else s ++ " ") ++ showCtxt
            showCtxt = "(@" ++ ctxt ++ ")"
            f st = show st ++ " // " ++ showThis

instance Exception ElfException

elfError :: MonadThrow m => String -> m a
elfError s = throwM $ ElfException s "#" Nothing

elfError' :: MonadThrow m => m a
elfError' = elfError []

addContext :: MonadCatch m => String -> m a -> m a
addContext s m = m `catch` f
    where
        f e = throwM $ ElfException s "#" $ Just e

addContext' :: MonadCatch m => m a -> m a
addContext' = addContext []
