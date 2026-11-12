//go:build (linux || darwin) && cgo

package gocades

/*
#include "gocades.h"
*/
import "C"

import (
	"bytes"
	"time"
	"unsafe"
)

// CRL mirrors CadesCRL: a certificate revocation list.
//
// The object keeps the encoding and the fields parsed at import, so it holds
// no CryptoAPI handle and needs no Close. The getters of an empty CRL (NewCRL
// without Import) return ErrNotInitialized.
type CRL struct {
	der        []byte
	issuer     string
	thisUpdate time.Time
	nextUpdate time.Time
	thumbprint string
	authKeyID  string
}

// NewCRL returns an empty CRL, like pycades.CRL().
func NewCRL() *CRL { return &CRL{} }

// ImportCRLDER parses a DER-encoded CRL.
func ImportCRLDER(der []byte) (*CRL, error) {
	c := NewCRL()
	if err := c.importDER("CRL.Import", der); err != nil {
		return nil, err
	}
	return c, nil
}

// Import replaces the CRL with the given representation, like CadesCRL.Import.
// As with Certificate.Import, the value is base64 or a raw binary string; PEM
// is not accepted.
func (c *CRL) Import(encoded string, t EncodingType) error {
	der, err := decodeEncodedData(encoded, t)
	if err != nil {
		return err
	}
	return c.importDER("CRL.Import", der)
}

func (c *CRL) importDER(op string, der []byte) error {
	if len(der) == 0 {
		return &Error{Op: op, Code: hrEInvalidArg}
	}
	var info C.cp_crl_info
	if err := hrErr(op, C.cp_crl_info_get(bytesPtr(der), C.size_t(len(der)), &info)); err != nil {
		return err
	}
	defer C.cp_crl_info_free(info)

	*c = CRL{
		der:        bytes.Clone(der),
		issuer:     bufString(info.issuer),
		thisUpdate: unixOrZero(int64(info.this_update)),
		nextUpdate: unixOrZero(int64(info.next_update)),
		thumbprint: bufString(info.thumbprint),
		authKeyID:  bufString(info.auth_key_id),
	}
	return nil
}

func (c *CRL) loaded() error {
	if c == nil || c.der == nil {
		return ErrNotInitialized
	}
	return nil
}

// Export returns the CRL as base64 or as a raw binary string, like
// CadesCRL.Export.
func (c *CRL) Export(t EncodingType) (string, error) {
	if err := c.loaded(); err != nil {
		return "", err
	}
	return NewEncodedData(c.der).Format(t)
}

// ExportDER returns the DER-encoded CRL.
func (c *CRL) ExportDER() ([]byte, error) {
	if err := c.loaded(); err != nil {
		return nil, err
	}
	return bytes.Clone(c.der), nil
}

// IssuerName returns the issuer as an X.500 string ("CN=..., O=..., C=RU"),
// like CadesCRL.IssuerName.
func (c *CRL) IssuerName() (string, error) {
	if err := c.loaded(); err != nil {
		return "", err
	}
	return c.issuer, nil
}

// ThisUpdate returns the issue time of the CRL, like CadesCRL.ThisUpdate.
func (c *CRL) ThisUpdate() (time.Time, error) {
	if err := c.loaded(); err != nil {
		return time.Time{}, err
	}
	return c.thisUpdate, nil
}

// NextUpdate returns the time by which the next CRL is due, like
// CadesCRL.NextUpdate; the zero time when the CRL does not say.
func (c *CRL) NextUpdate() (time.Time, error) {
	if err := c.loaded(); err != nil {
		return time.Time{}, err
	}
	return c.nextUpdate, nil
}

// Thumbprint returns the SHA-1 hash of the encoding in upper-case hex, like
// CadesCRL.Thumbprint.
func (c *CRL) Thumbprint() (string, error) {
	if err := c.loaded(); err != nil {
		return "", err
	}
	return c.thumbprint, nil
}

// AuthKeyID returns the keyIdentifier of the authorityKeyIdentifier extension
// in upper-case hex, like CadesCRL.AuthKeyID; empty when the CRL has none.
func (c *CRL) AuthKeyID() (string, error) {
	if err := c.loaded(); err != nil {
		return "", err
	}
	return c.authKeyID, nil
}

func bufString(b C.cp_buf) string {
	return C.GoStringN((*C.char)(unsafe.Pointer(b.data)), C.int(b.len))
}
