{-# OPTIONS_GHC -Wall -fwarn-tabs #-}
{-# LANGUAGE TemplateHaskell #-}

module Data.Elf.TH (mkDeclarations) where

import Control.Monad
import Language.Haskell.TH

mkDeclarations :: Name -> String -> String -> String -> [(String, Integer)] -> Q [Dec]
mkDeclarations baseTypeName typeNameString patternPrefixString defaultPatternNameString enums = do

    let typeName = mkName typeNameString
    let patternName s = mkName (patternPrefixString ++ s)
    let defaultPatternName = mkName defaultPatternNameString

    let newTypeDef = newtypeD
                (cxt [])
                typeName
                []
                Nothing
                (normalC typeName [ bangType (bang noSourceUnpackedness noSourceStrictness) (conT baseTypeName) ])
                [ derivClause Nothing [ conT (mkName "Eq") ] ]

    let
        mkShowClause (s, n) = clause
                                [ conP typeName [litP $ IntegerL n] ]
                                (normalB [| patternPrefixString ++ s |])
                                []

    let showClauses = map mkShowClause enums

    localName <- newName "n"
    let defaultShowClause = clause
                                [ conP typeName [varP localName] ]
                                (normalB [| typeNameString ++ " " ++ show $(varE localName) |])
                                []

    let showInstanceFunctions = funD (mkName "show") (showClauses ++ [ defaultShowClause ])

    let showInstance = instanceD (cxt []) (appT (conT (mkName "Show")) (conT typeName)) [ showInstanceFunctions ]

    let
        newNamePE s = do
            n <- newName s
            return (varP n, varE n)

    (n3P, n3E) <- newNamePE "n"
    let binaryInstancePut = funD
                                (mkName "put")
                                [ clause
                                    [conP typeName [n3P]]
                                    (normalB
                                        (appE
                                            (varE $ mkName "put")
                                            n3E))
                                    []
                                ]

    let binaryInstanceGet = funD
                                (mkName "get")
                                [ clause
                                    []
                                    (normalB
                                        (uInfixE
                                            (conE typeName)
                                            (varE $ mkName "<$>")
                                            (varE $ mkName "get")))
                                    []
                                ]

    let binaryInstance = instanceD (cxt []) (appT (conT (mkName "Binary")) (conT typeName)) [ binaryInstanceGet, binaryInstancePut ]

    let
        mkPatterns (s, n) =
            [ patSynSigD (patternName s) (conT typeName)
            , patSynD (patternName s) (prefixPatSyn []) implBidir (conP typeName [litP $ IntegerL n])
            ]

    let defaultPatternSig = patSynSigD defaultPatternName (appT (appT arrowT (conT baseTypeName)) (conT typeName))
    localName2 <- newName "n"
    let defaultPatternDef = patSynD defaultPatternName (prefixPatSyn [localName2]) implBidir (conP typeName [varP localName2])

    let patterns = (join $ map mkPatterns enums) ++ [ defaultPatternSig, defaultPatternDef ]

    sequence $ newTypeDef : showInstance : binaryInstance : patterns
