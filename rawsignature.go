//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"errors"
	"runtime"
)

// RawSignature mirrors CadesRawSignature: a signature over a digest, without
// any CMS wrapper.
//
// The signature is produced by CryptSignHash in the byte order used by the CSP;
// verify it with the same provider.
type RawSignature struct{}

// NewRawSignature returns an empty RawSignature, like pycades.RawSignature().
func NewRawSignature() *RawSignature { return &RawSignature{} }

// SignHash signs the digest held by hashed, like CadesRawSignature.SignHash.
func (r *RawSignature) SignHash(cert *Certificate, hashed *HashedData) ([]byte, error) {
	if hashed == nil {
		return nil, errors.New("gocades: nil HashedData")
	}
	return r.SignDigest(cert, hashed.Value())
}

// SignDigest signs a raw digest.
func (r *RawSignature) SignDigest(cert *Certificate, digest []byte) ([]byte, error) {
	h, err := cert.handle()
	if err != nil {
		return nil, err
	}
	if len(digest) == 0 {
		return nil, &Error{Op: "RawSignature.SignHash", Code: hrEInvalidArg}
	}

	var out C.cp_buf
	rc := C.cp_raw_sign_hash(h, bytesPtr(digest), C.size_t(len(digest)), &out)
	runtime.KeepAlive(cert)

	if rc != 0 {
		return nil, hrErr("RawSignature.SignHash", rc)
	}
	return bufToBytes(out), nil
}

// VerifyHash verifies a raw signature over the digest held by hashed, like
// CadesRawSignature.VerifyHash.
func (r *RawSignature) VerifyHash(cert *Certificate, hashed *HashedData, sig []byte) error {
	if hashed == nil {
		return errors.New("gocades: nil HashedData")
	}
	return r.VerifyDigest(cert, hashed.Value(), sig)
}

// VerifyDigest verifies a raw signature over a digest.
func (r *RawSignature) VerifyDigest(cert *Certificate, digest, sig []byte) error {
	h, err := cert.handle()
	if err != nil {
		return err
	}
	if len(digest) == 0 || len(sig) == 0 {
		return &Error{Op: "RawSignature.VerifyHash", Code: hrEInvalidArg}
	}

	rc := C.cp_raw_verify_hash(h,
		bytesPtr(digest), C.size_t(len(digest)),
		bytesPtr(sig), C.size_t(len(sig)))
	runtime.KeepAlive(cert)

	if rc == 0 {
		return nil
	}
	if rc == C.int32_t(hrNTEBadSignature) {
		return ErrBadSignature
	}
	return hrErr("RawSignature.VerifyHash", rc)
}
