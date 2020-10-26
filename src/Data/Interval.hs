-- This differs from intervals package: even an empty interval has offset (but not inf)

module Data.Interval
    ( Interval(..)
    , member
    ) where

data Interval a = I { offset :: !a, size :: !a } deriving (Eq, Ord)

member :: (Ord a, Num a) => a -> Interval a -> Bool
member _ (I _ s) | s <= 0    = False
member x (I o s) | otherwise = o <= x && x <= (o + s - 1)
{-# INLINE member #-}
