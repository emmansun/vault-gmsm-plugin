package gmsm

import (
	"hash"

	"github.com/emmansun/gmsm/sm3"
)

type HashType uint32

const (
	HashTypeNone HashType = iota
	HashTypeSM3
)

var (
	HashTypeMap = map[string]HashType{
		"none": HashTypeNone,
		"sm3":  HashTypeSM3,
	}

	HashFuncMap = map[HashType]func() hash.Hash{
		HashTypeNone: nil,
		HashTypeSM3:  sm3.New,
	}
)
