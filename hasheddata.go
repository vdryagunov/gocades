//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

// HashAlg mirrors CAPICOM_HASH_ALGORITHM.
type HashAlg int32

const (
	HashAlgSHA1   HashAlg = 0
	HashAlgMD2    HashAlg = 1
	HashAlgMD4    HashAlg = 2
	HashAlgMD5    HashAlg = 3
	HashAlgSHA256 HashAlg = 4
	HashAlgSHA384 HashAlg = 5
	HashAlgSHA512 HashAlg = 6

	HashAlgGOST3411          HashAlg = 100
	HashAlgGOST3411_2012_256 HashAlg = 101
	HashAlgGOST3411_2012_512 HashAlg = 102

	HashAlgGOST3411HMAC           HashAlg = 110
	HashAlgGOST3411_2012_256_HMAC HashAlg = 111
	HashAlgGOST3411_2012_512_HMAC HashAlg = 112
)

func (a HashAlg) String() string {
	switch a {
	case HashAlgSHA1:
		return "SHA1"
	case HashAlgMD2:
		return "MD2"
	case HashAlgMD4:
		return "MD4"
	case HashAlgMD5:
		return "MD5"
	case HashAlgSHA256:
		return "SHA256"
	case HashAlgSHA384:
		return "SHA384"
	case HashAlgSHA512:
		return "SHA512"
	case HashAlgGOST3411:
		return "GOST3411"
	case HashAlgGOST3411_2012_256:
		return "GOST3411_2012_256"
	case HashAlgGOST3411_2012_512:
		return "GOST3411_2012_512"
	case HashAlgGOST3411HMAC:
		return "GOST3411_HMAC"
	case HashAlgGOST3411_2012_256_HMAC:
		return "GOST3411_2012_256_HMAC"
	case HashAlgGOST3411_2012_512_HMAC:
		return "GOST3411_2012_512_HMAC"
	}
	return "UNKNOWN"
}

// HashedData mirrors CadesHashedData.
//
// Hash is a one-shot operation: it replaces Value with the digest of the
// supplied data. SetHashValue installs an externally computed digest.
type HashedData struct {
	algorithm HashAlg
	encoding  EncodingType
	key       []byte
	value     []byte
}

// NewHashedData returns a HashedData defaulting to GOST R 34.11-2012 (256 bit).
func NewHashedData() *HashedData {
	return &HashedData{
		algorithm: HashAlgGOST3411_2012_256,
		encoding:  EncodingBinary,
	}
}

// SetAlgorithm selects the digest algorithm.
func (h *HashedData) SetAlgorithm(a HashAlg) { h.algorithm = a }

// Algorithm returns the selected digest algorithm.
func (h *HashedData) Algorithm() HashAlg { return h.algorithm }

// SetDataEncoding records the presentation of Value; it does not affect hashing.
func (h *HashedData) SetDataEncoding(t EncodingType) { h.encoding = t }

// DataEncoding returns the configured presentation.
func (h *HashedData) DataEncoding() EncodingType { return h.encoding }

// SetKey sets the HMAC key. It is used only with the *_HMAC algorithms, which
// require it; plain digest algorithms ignore it.
func (h *HashedData) SetKey(k []byte) { h.key = k }

// Key returns the HMAC key.
func (h *HashedData) Key() []byte { return h.key }

// Value returns the current digest.
func (h *HashedData) Value() []byte { return h.value }

// SetHashValue installs an externally computed digest, like
// CadesHashedData.SetHashValue.
func (h *HashedData) SetHashValue(v []byte) error {
	if len(v) == 0 {
		return &Error{Op: "HashedData.SetHashValue", Code: hrEInvalidArg}
	}
	h.value = v
	return nil
}

// Hash computes the digest of data, like CadesHashedData.Hash. For the
// *_HMAC algorithms it computes HMAC (RFC 2104) with the key set by SetKey.
func (h *HashedData) Hash(data []byte) error {
	var (
		v   []byte
		err error
	)
	if base, ok := hmacBase(h.algorithm); ok {
		if len(h.key) == 0 {
			return &Error{Op: "HashedData.Hash (HMAC without a key)", Code: hrEInvalidArg}
		}
		v, err = hmacDigest(base, h.key, data)
	} else {
		v, err = digest(h.algorithm, data)
	}
	if err != nil {
		return err
	}
	h.value = v
	return nil
}

// digest hashes data with a plain digest algorithm through the CSP.
func digest(alg HashAlg, data []byte) ([]byte, error) {
	var out C.cp_buf
	rc := C.cp_hash(C.int32_t(alg), bytesPtr(data), C.size_t(len(data)), &out)
	if rc != 0 {
		return nil, hrErr("HashedData.Hash", rc)
	}
	return bufToBytes(out), nil
}

// hmacBase returns the digest an HMAC algorithm is built on.
func hmacBase(a HashAlg) (HashAlg, bool) {
	switch a {
	case HashAlgGOST3411HMAC:
		return HashAlgGOST3411, true
	case HashAlgGOST3411_2012_256_HMAC:
		return HashAlgGOST3411_2012_256, true
	case HashAlgGOST3411_2012_512_HMAC:
		return HashAlgGOST3411_2012_512, true
	}
	return 0, false
}

// hashBlockSize is the input block size used by HMAC: 64 bytes for
// GOST R 34.11-2012 (RFC 7836) and 32 bytes for GOST R 34.11-94 (RFC 4357).
func hashBlockSize(a HashAlg) int {
	if a == HashAlgGOST3411 {
		return 32
	}
	return 64
}

// hmacDigest computes HMAC(key, data) = H((K ^ opad) || H((K ^ ipad) || data)).
func hmacDigest(base HashAlg, key, data []byte) ([]byte, error) {
	block := hashBlockSize(base)
	if len(key) > block {
		k, err := digest(base, key)
		if err != nil {
			return nil, err
		}
		key = k
	}

	ipad := make([]byte, block, block+len(data))
	opad := make([]byte, block)
	copy(ipad, key)
	copy(opad, key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}

	inner, err := digest(base, append(ipad, data...))
	if err != nil {
		return nil, err
	}
	return digest(base, append(opad, inner...))
}
