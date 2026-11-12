//go:build (linux || darwin) && cgo

package gocades

import "hash"

// gostHash adapts the one-shot CSP hasher to hash.Hash by buffering the input.
//
// The CryptoPro provider exposes no incremental interface, so the digest is
// computed when Sum is called. Everything written is kept in memory.
type gostHash struct {
	alg HashAlg
	buf []byte
}

func (h *gostHash) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

func (h *gostHash) Sum(b []byte) []byte {
	hd := NewHashedData()
	hd.SetAlgorithm(h.alg)

	// hash.Hash cannot report an error. A failure here means the CSP is not
	// usable at all, so fail loudly instead of returning a bogus digest.
	if err := hd.Hash(h.buf); err != nil {
		panic("gocades: GOST hashing failed: " + err.Error())
	}
	return append(b, hd.Value()...)
}

func (h *gostHash) Reset() { h.buf = h.buf[:0] }

func (h *gostHash) Size() int {
	if h.alg == HashAlgGOST3411_2012_512 {
		return 64
	}
	return 32
}

func (h *gostHash) BlockSize() int { return hashBlockSize(h.alg) }

// NewGOST3411_2012_256 returns a hash.Hash computing GOST R 34.11-2012 with a
// 256-bit digest through the CryptoPro CSP.
//
// It is a regular hash.Hash, so it can be handed to any consumer that needs
// one; the internal PAdES layer uses it as the digest implementation for PDF
// signatures.
func NewGOST3411_2012_256() hash.Hash {
	return &gostHash{alg: HashAlgGOST3411_2012_256}
}

// NewGOST3411_2012_512 returns a hash.Hash computing GOST R 34.11-2012 with a
// 512-bit digest through the CryptoPro CSP.
func NewGOST3411_2012_512() hash.Hash {
	return &gostHash{alg: HashAlgGOST3411_2012_512}
}

// NewGOST3411 returns a hash.Hash computing the legacy GOST R 34.11-94 digest.
func NewGOST3411() hash.Hash {
	return &gostHash{alg: HashAlgGOST3411}
}
