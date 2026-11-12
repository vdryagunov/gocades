//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include <string.h>
#include "gocades.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// Certificate is an opaque handle to a CryptoPro certificate context.
//
// Methods called after Close return ErrClosed.
type Certificate struct {
	h unsafe.Pointer
	// additional is an extra store consulted when building chains in IsValid.
	additional *Store
}

func newCertificate(h unsafe.Pointer) *Certificate {
	c := &Certificate{h: h}
	runtime.SetFinalizer(c, (*Certificate).Close)
	return c
}

// handle returns the certificate context, or ErrNilCertificate / ErrClosed.
//
// The caller must keep c alive (runtime.KeepAlive) until the C call that uses
// the handle returns: otherwise the finalizer may free the context mid-call.
func (c *Certificate) handle() (unsafe.Pointer, error) {
	if c == nil {
		return nil, ErrNilCertificate
	}
	if c.h == nil {
		return nil, ErrClosed
	}
	return c.h, nil
}

// dup returns an independent reference to the same certificate context, or
// nil for a nil or closed certificate.
func (c *Certificate) dup() *Certificate {
	if c == nil || c.h == nil {
		return nil
	}
	h := C.cp_cert_dup(c.h)
	runtime.KeepAlive(c)
	if h == nil {
		return nil
	}
	return newCertificate(h)
}

// Close releases the certificate context.
func (c *Certificate) Close() {
	if c != nil && c.h != nil {
		C.cp_cert_free(c.h)
		c.h = nil
		runtime.SetFinalizer(c, nil)
	}
}

// ImportCertificateDER creates a certificate context from a DER-encoded X.509
// certificate. The resulting context has no private key association.
func ImportCertificateDER(der []byte) (*Certificate, error) {
	var h unsafe.Pointer
	if err := hrErr("Certificate.ImportDER",
		C.cp_cert_import_der(&h, bytesPtr(der), C.size_t(len(der)))); err != nil {
		return nil, err
	}
	return newCertificate(h), nil
}

// certString runs one of the cp_cert_* string getters.
func (c *Certificate) certString(op string, get func(unsafe.Pointer, *C.cp_buf) C.int32_t) (string, error) {
	h, err := c.handle()
	if err != nil {
		return "", err
	}
	var b C.cp_buf
	rc := get(h, &b)
	runtime.KeepAlive(c)
	if err := hrErr(op, rc); err != nil {
		return "", err
	}
	return string(bufToBytes(b)), nil
}

// SubjectName returns the certificate subject simple display name.
func (c *Certificate) SubjectName() (string, error) {
	return c.certString("Certificate.SubjectName", func(h unsafe.Pointer, b *C.cp_buf) C.int32_t {
		return C.cp_cert_subject(h, b)
	})
}

// IssuerName returns the certificate issuer simple display name.
func (c *Certificate) IssuerName() (string, error) {
	return c.certString("Certificate.IssuerName", func(h unsafe.Pointer, b *C.cp_buf) C.int32_t {
		return C.cp_cert_issuer(h, b)
	})
}

// SerialNumber returns the certificate serial number as a hex string.
func (c *Certificate) SerialNumber() (string, error) {
	return c.certString("Certificate.SerialNumber", func(h unsafe.Pointer, b *C.cp_buf) C.int32_t {
		return C.cp_cert_serial(h, b)
	})
}

// Thumbprint returns the SHA-1 thumbprint as a lowercase hex string.
func (c *Certificate) Thumbprint() (string, error) {
	return c.certString("Certificate.Thumbprint", func(h unsafe.Pointer, b *C.cp_buf) C.int32_t {
		return C.cp_cert_thumbprint(h, b)
	})
}

// ExportDER returns the DER-encoded certificate.
func (c *Certificate) ExportDER() ([]byte, error) {
	h, err := c.handle()
	if err != nil {
		return nil, err
	}
	var b C.cp_buf
	rc := C.cp_cert_export_der(h, &b)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.ExportDER", rc); err != nil {
		return nil, err
	}
	return bufToBytes(b), nil
}

// Export returns the certificate as base64 or as a raw binary string, like
// CadesCertificate.Export.
func (c *Certificate) Export(t EncodingType) (string, error) {
	der, err := c.ExportDER()
	if err != nil {
		return "", err
	}
	return NewEncodedData(der).Format(t)
}

// Import replaces the certificate contents with the given representation, like
// CadesCertificate.Import.
func (c *Certificate) Import(encoded string, t EncodingType) error {
	if c == nil {
		return ErrNilCertificate
	}
	der, err := decodeEncodedData(encoded, t)
	if err != nil {
		return err
	}

	var h unsafe.Pointer
	if err := hrErr("Certificate.Import",
		C.cp_cert_import_der(&h, bytesPtr(der), C.size_t(len(der)))); err != nil {
		return err
	}

	// Swap the context: the old one is released, the new one adopted.
	c.Close()
	c.h = h
	runtime.SetFinalizer(c, (*Certificate).Close)
	return nil
}

// HasPrivateKey reports whether a private key container is associated with
// the certificate. A closed certificate has none.
func (c *Certificate) HasPrivateKey() bool {
	h, err := c.handle()
	if err != nil {
		return false
	}
	ok := C.cp_cert_has_private_key(h) != 0
	runtime.KeepAlive(c)
	return ok
}

// SetPIN unlocks the certificate's key container with pin.
//
// The unlocked provider is attached to the certificate context
// (CERT_KEY_CONTEXT_PROP_ID), so later signing operations with this
// certificate do not prompt for the PIN. The context is shared by every
// Certificate value that refers to the same certificate of a store.
//
// The property owns the provider: CryptoPro releases it when the property is
// replaced (another SetPIN) or the last reference to the context is freed.
// There is nothing to release separately, and closing one Certificate value
// does not lock the others.
func (c *Certificate) SetPIN(pin string) error {
	h, err := c.handle()
	if err != nil {
		return err
	}
	cpin := C.CString(pin)
	defer freeSecret(cpin, len(pin))

	rc := C.cp_cert_set_pin(h, cpin)
	runtime.KeepAlive(c)
	return hrErr("Certificate.SetPIN", rc)
}

// freeSecret wipes and frees a C copy of a secret such as a PIN.
func freeSecret(p *C.char, n int) {
	if n > 0 {
		C.memset(unsafe.Pointer(p), 0, C.size_t(n))
	}
	C.free(unsafe.Pointer(p))
}
