package pdfsign

import (
	"context"
	"crypto/sha256"
	"hash"
)

// HashAlgorithm is the digest algorithm applied to the PDF /ByteRange.
type HashAlgorithm int32

const (
	// HashGOST3411_2012_256 is GOST R 34.11-2012 with a 256-bit digest. It has
	// no pure-Go implementation here: pass Options.NewHash.
	HashGOST3411_2012_256 HashAlgorithm = iota
	// HashSHA256 is SHA-256, available in the standard library.
	HashSHA256
)

func (a HashAlgorithm) String() string {
	switch a {
	case HashGOST3411_2012_256:
		return "gost3411-2012-256"
	case HashSHA256:
		return "sha256"
	}
	return "unknown"
}

// CMSProvider produces a detached CMS/CAdES signature over a precomputed
// digest of the PDF /ByteRange.
//
// The implementation is supplied by the caller: the cades package signs with a
// CryptoPro key container, and tests can use an in-memory implementation. The
// backend variant of the same interface signs a digest produced by the browser
// plug-in.
type CMSProvider interface {
	SignDetachedHash(ctx context.Context, digest []byte, alg HashAlgorithm) ([]byte, error)
}

// SignPDF is the digest-based convenience path: prepare, sign the digest,
// assemble. It requires a hasher for the selected algorithm.
func SignPDF(ctx context.Context, provider CMSProvider, pdf []byte, opts Options) ([]byte, error) {
	prepared, err := Prepare(pdf, opts)
	if err != nil {
		return nil, err
	}
	if prepared.Digest == nil {
		return nil, ErrNoHasher
	}

	cms, err := provider.SignDetachedHash(ctx, prepared.Digest, prepared.Hash)
	if err != nil {
		return nil, err
	}

	return prepared.Assemble(cms)
}

// hashFactory resolves the digest implementation. ok is false when the
// algorithm has no implementation, which only rules out the digest-based flow.
func (o Options) hashFactory() (factory func() hash.Hash, alg HashAlgorithm, ok bool) {
	alg = o.Hash
	if o.NewHash != nil {
		return o.NewHash, alg, true
	}
	if alg == HashSHA256 {
		return sha256.New, alg, true
	}
	return nil, alg, false
}
