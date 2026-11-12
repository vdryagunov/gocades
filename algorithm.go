//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import "unsafe"

// EncryptionAlgorithm mirrors CADESCOM_ENCRYPTION_ALGORITHM.
type EncryptionAlgorithm int32

const (
	EncryptionRC2       EncryptionAlgorithm = 0
	EncryptionRC4       EncryptionAlgorithm = 1
	EncryptionDES       EncryptionAlgorithm = 2
	Encryption3DES      EncryptionAlgorithm = 3
	EncryptionAES       EncryptionAlgorithm = 4
	EncryptionGOST28147 EncryptionAlgorithm = 25
)

// String returns the pycades-style enum name.
func (a EncryptionAlgorithm) String() string {
	switch a {
	case EncryptionRC2:
		return "RC2"
	case EncryptionRC4:
		return "RC4"
	case EncryptionDES:
		return "DES"
	case Encryption3DES:
		return "3DES"
	case EncryptionAES:
		return "AES"
	case EncryptionGOST28147:
		return "GOST_28147_89"
	}
	return "UNKNOWN"
}

// EncryptionKeyLength mirrors CAPICOM_ENCRYPTION_KEY_LENGTH.
type EncryptionKeyLength int32

const (
	KeyLengthMaximum EncryptionKeyLength = 0
	KeyLength40      EncryptionKeyLength = 1
	KeyLength56      EncryptionKeyLength = 2
	KeyLength128     EncryptionKeyLength = 3
	KeyLength192     EncryptionKeyLength = 4
	KeyLength256     EncryptionKeyLength = 5
)

// Algorithm mirrors CadesAlgorithm: the encryption algorithm selector used by
// HashedData, EnvelopedData and SymmetricAlgorithm.
//
// It is not a description of a key; PublicKey.Algorithm returns an OID.
type Algorithm struct {
	Name      EncryptionAlgorithm
	KeyLength EncryptionKeyLength
}

// ProviderAlgorithm describes an algorithm implemented by the installed CSP.
type ProviderAlgorithm struct {
	Name        string
	LongName    string
	ID          uint32
	DefaultBits uint32
	MinBits     uint32
	MaxBits     uint32
	Protocols   uint32
}

// ProviderAlgorithms enumerates the algorithms of the installed CSP
// (PP_ENUMALGS_EX).
//
// This is an extension over pycades, intended for installation diagnostics.
func ProviderAlgorithms() ([]ProviderAlgorithm, error) {
	var l C.cp_alg_list
	if err := hrErr("ProviderAlgorithms", C.cp_provider_algorithms(&l)); err != nil {
		return nil, err
	}
	defer C.cp_alg_list_free(l)

	if l.len == 0 {
		return nil, nil
	}

	items := unsafe.Slice(l.items, int(l.len))
	out := make([]ProviderAlgorithm, 0, len(items))
	for _, it := range items {
		out = append(out, ProviderAlgorithm{
			Name:        C.GoString(it.name),
			LongName:    C.GoString(it.long_name),
			ID:          uint32(it.alg_id),
			DefaultBits: uint32(it.default_bits),
			MinBits:     uint32(it.min_bits),
			MaxBits:     uint32(it.max_bits),
			Protocols:   uint32(it.protocols),
		})
	}
	return out, nil
}
