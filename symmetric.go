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
	"unsafe"
)

// CipherMode mirrors the CryptoAPI CRYPT_MODE_* constants.
type CipherMode uint32

const (
	ModeECB CipherMode = 1
	ModeCBC CipherMode = 2
	ModeCFB CipherMode = 3
	ModeOFB CipherMode = 4
)

// Padding mirrors the CryptoAPI KP_PADDING values.
type Padding uint32

const (
	// PaddingPKCS5 is PKCS#5 / PKCS#7 padding.
	PaddingPKCS5 Padding = 1
	// PaddingRandom is random padding.
	PaddingRandom Padding = 2
	// PaddingZero is zero padding.
	PaddingZero Padding = 3
)

// SymmetricAlgorithm mirrors CadesSymmetricAlgorithm.
//
// The key lives in the CSP session object, so the value carries a finalizer.
// Methods called after Close return ErrClosed.
type SymmetricAlgorithm struct {
	h        unsafe.Pointer
	divers   []byte
	finished bool
}

// NewSymmetricAlgorithm creates an empty symmetric session.
func NewSymmetricAlgorithm() (*SymmetricAlgorithm, error) {
	h := C.cp_sym_new()
	if h == nil {
		return nil, errors.New("gocades: cannot allocate a symmetric session")
	}

	s := &SymmetricAlgorithm{h: h}
	runtime.SetFinalizer(s, (*SymmetricAlgorithm).Close)
	return s, nil
}

// handle returns the session handle, or ErrClosed. The caller must keep s
// alive until the C call that uses the handle returns.
func (s *SymmetricAlgorithm) handle() (unsafe.Pointer, error) {
	if s == nil || s.h == nil {
		return nil, ErrClosed
	}
	return s.h, nil
}

// Close destroys the session key and releases the provider.
func (s *SymmetricAlgorithm) Close() {
	if s != nil && s.h != nil {
		C.cp_sym_free(s.h)
		s.h = nil
		s.finished = true
		runtime.SetFinalizer(s, nil)
	}
}

// GenerateKey creates a new session key, like
// CadesSymmetricAlgorithm.GenerateKey.
func (s *SymmetricAlgorithm) GenerateKey(a EncryptionAlgorithm) error {
	return s.generate(a, 0)
}

// GenerateKeyBits is GenerateKey with an explicit key size; 0 means the
// provider default.
func (s *SymmetricAlgorithm) GenerateKeyBits(a EncryptionAlgorithm, bits uint32) error {
	return s.generate(a, bits)
}

func (s *SymmetricAlgorithm) generate(a EncryptionAlgorithm, bits uint32) error {
	h, err := s.handle()
	if err != nil {
		return err
	}
	rc := C.cp_sym_generate(h, C.int32_t(a), C.uint32_t(bits))
	runtime.KeepAlive(s)
	return hrErr("SymmetricAlgorithm.GenerateKey", rc)
}

// SetMode selects the cipher mode, like CadesSymmetricAlgorithm.SetMode.
func (s *SymmetricAlgorithm) SetMode(mode CipherMode) error {
	h, err := s.handle()
	if err != nil {
		return err
	}
	rc := C.cp_sym_set_mode(h, C.uint32_t(mode))
	runtime.KeepAlive(s)
	return hrErr("SymmetricAlgorithm.SetMode", rc)
}

// SetPadding selects the padding, like CadesSymmetricAlgorithm.SetPadding.
func (s *SymmetricAlgorithm) SetPadding(p Padding) error {
	h, err := s.handle()
	if err != nil {
		return err
	}
	rc := C.cp_sym_set_padding(h, C.uint32_t(p))
	runtime.KeepAlive(s)
	return hrErr("SymmetricAlgorithm.SetPadding", rc)
}

// IV returns the current initialization vector, like
// CadesSymmetricAlgorithm.IV.
func (s *SymmetricAlgorithm) IV() ([]byte, error) {
	h, err := s.handle()
	if err != nil {
		return nil, err
	}

	var b C.cp_buf
	rc := C.cp_sym_get_iv(h, &b)
	runtime.KeepAlive(s)
	if err := hrErr("SymmetricAlgorithm.IV", rc); err != nil {
		return nil, err
	}
	return bufToBytes(b), nil
}

// SetIV installs an initialization vector.
func (s *SymmetricAlgorithm) SetIV(iv []byte) error {
	h, err := s.handle()
	if err != nil {
		return err
	}
	if len(iv) == 0 {
		return &Error{Op: "SymmetricAlgorithm.SetIV", Code: hrEInvalidArg}
	}

	rc := C.cp_sym_set_iv(h, bytesPtr(iv), C.size_t(len(iv)))
	runtime.KeepAlive(s)
	return hrErr("SymmetricAlgorithm.SetIV", rc)
}

// Encrypt encrypts data, like CadesSymmetricAlgorithm.Encrypt.
func (s *SymmetricAlgorithm) Encrypt(data []byte) ([]byte, error) {
	h, err := s.handle()
	if err != nil {
		return nil, err
	}

	var out C.cp_buf
	rc := C.cp_sym_encrypt(h, bytesPtr(data), C.size_t(len(data)), &out)
	runtime.KeepAlive(s)

	if rc != 0 {
		return nil, hrErr("SymmetricAlgorithm.Encrypt", rc)
	}
	return bufToBytes(out), nil
}

// Decrypt decrypts data, like CadesSymmetricAlgorithm.Decrypt.
func (s *SymmetricAlgorithm) Decrypt(data []byte) ([]byte, error) {
	h, err := s.handle()
	if err != nil {
		return nil, err
	}

	var out C.cp_buf
	rc := C.cp_sym_decrypt(h, bytesPtr(data), C.size_t(len(data)), &out)
	runtime.KeepAlive(s)

	if rc != 0 {
		return nil, hrErr("SymmetricAlgorithm.Decrypt", rc)
	}
	return bufToBytes(out), nil
}

// SetDiversData records the diversification data.
//
// It is kept for API parity; DiversifyKey is not implemented yet.
func (s *SymmetricAlgorithm) SetDiversData(d []byte) { s.divers = d }

// DiversData returns the diversification data.
func (s *SymmetricAlgorithm) DiversData() []byte { return s.divers }

// ExportKey exports the session key protected with a recipient certificate,
// like CadesSymmetricAlgorithm.ExportKey.
func (s *SymmetricAlgorithm) ExportKey(cert *Certificate) ([]byte, error) {
	h, err := s.handle()
	if err != nil {
		return nil, err
	}
	hc, err := cert.handle()
	if err != nil {
		return nil, err
	}

	var out C.cp_buf
	rc := C.cp_sym_export_key(h, hc, &out)
	runtime.KeepAlive(s)
	runtime.KeepAlive(cert)
	if rc != 0 {
		return nil, hrErr("SymmetricAlgorithm.ExportKey", rc)
	}
	return bufToBytes(out), nil
}

// ImportKey imports a session key previously exported by ExportKey.
//
// The key is protected with the recipient public key, so the same certificate
// must be supplied.
func (s *SymmetricAlgorithm) ImportKey(cert *Certificate, key []byte) error {
	h, err := s.handle()
	if err != nil {
		return err
	}
	hc, err := cert.handle()
	if err != nil {
		return err
	}
	if len(key) == 0 {
		return &Error{Op: "SymmetricAlgorithm.ImportKey", Code: hrEInvalidArg}
	}

	rc := C.cp_sym_import_key(h, hc, bytesPtr(key), C.size_t(len(key)))
	runtime.KeepAlive(s)
	runtime.KeepAlive(cert)
	return hrErr("SymmetricAlgorithm.ImportKey", rc)
}

// DiversifyKey derives a key from DiversData.
//
// Not implemented: the provider-specific diversification parameters
// (KP_SALT / UECMASTER) are not wrapped yet.
func (s *SymmetricAlgorithm) DiversifyKey() error {
	return ErrUnsupported
}
