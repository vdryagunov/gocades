//go:build (linux || darwin) && cgo

package gocades

/*
#include "gocades.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"time"
)

// OIDPrivateKeyUsagePeriod is the PrivateKeyUsagePeriod extension.
const OIDPrivateKeyUsagePeriod = "2.5.29.16"

// Extension mirrors CadesExtension: one certificate extension.
type Extension struct {
	OID        *OID
	IsCritical bool
	// EncodedData is the DER extnValue (the contents of the OCTET STRING).
	EncodedData *EncodedData
}

// Extensions mirrors CadesExtensions.
type Extensions struct {
	items []Extension
}

// Count returns the number of extensions.
func (e Extensions) Count() int { return len(e.items) }

// Item returns the extension at index i.
func (e Extensions) Item(i int) (Extension, error) {
	if i < 0 || i >= len(e.items) {
		return Extension{}, fmt.Errorf("gocades: extension index %d out of range [0,%d)", i, len(e.items))
	}
	return e.items[i], nil
}

// All returns the extensions in certificate order.
func (e Extensions) All() []Extension { return append([]Extension(nil), e.items...) }

// Find returns the extension with the given OID.
func (e Extensions) Find(oid string) (Extension, bool) {
	for _, x := range e.items {
		if x.OID.Value == oid {
			return x, true
		}
	}
	return Extension{}, false
}

// Extensions returns every extension of the certificate, like
// CadesCertificate.Extensions.
func (c *Certificate) Extensions() (Extensions, error) {
	h, err := c.handle()
	if err != nil {
		return Extensions{}, err
	}
	defer runtime.KeepAlive(c)

	var n C.size_t
	if err := hrErr("Certificate.Extensions", C.cp_cert_extension_count(h, &n)); err != nil {
		return Extensions{}, err
	}
	items := make([]Extension, 0, int(n))
	for i := C.size_t(0); i < n; i++ {
		var (
			oid, value C.cp_buf
			critical   C.int32_t
		)
		if err := hrErr("Certificate.Extensions",
			C.cp_cert_extension_at(h, i, &oid, &critical, &value)); err != nil {
			return Extensions{}, err
		}
		items = append(items, Extension{
			OID:         NewOID(string(bufToBytes(oid))),
			IsCritical:  critical != 0,
			EncodedData: NewEncodedData(bufToBytes(value)),
		})
	}
	return Extensions{items: items}, nil
}

// PrivateKeyUsagePeriodFrom returns notBefore of the PrivateKeyUsagePeriod
// extension, like CadesCertificate.PrivateKeyUsagePeriodFrom. Without the
// extension or the field the error is CRYPT_E_NOT_FOUND, as in CAdESCOM.
func (c *Certificate) PrivateKeyUsagePeriodFrom() (time.Time, error) {
	from, _, err := c.privateKeyUsagePeriod("Certificate.PrivateKeyUsagePeriodFrom", true)
	return from, err
}

// PrivateKeyUsagePeriodTo returns notAfter of the PrivateKeyUsagePeriod
// extension, like CadesCertificate.PrivateKeyUsagePeriodTo.
func (c *Certificate) PrivateKeyUsagePeriodTo() (time.Time, error) {
	_, to, err := c.privateKeyUsagePeriod("Certificate.PrivateKeyUsagePeriodTo", false)
	return to, err
}

func (c *Certificate) privateKeyUsagePeriod(op string, wantFrom bool) (time.Time, time.Time, error) {
	exts, err := c.Extensions()
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	ext, ok := exts.Find(OIDPrivateKeyUsagePeriod)
	if !ok {
		return time.Time{}, time.Time{}, &Error{Op: op, Code: hrCryptENotFound}
	}
	from, to, err := parsePrivateKeyUsagePeriod(ext.EncodedData.Value())
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%s: %w", op, err)
	}
	if (wantFrom && from.IsZero()) || (!wantFrom && to.IsZero()) {
		return time.Time{}, time.Time{}, &Error{Op: op, Code: hrCryptENotFound}
	}
	return from, to, nil
}

// IsMsgType reports whether signer 0 of the CMS msg is of type t, like
// CadesSignedData.IsMsgType (which decodes base64; pass DER here).
func IsMsgType(msg []byte, t CadesType) (bool, error) {
	if len(msg) == 0 {
		return false, &Error{Op: "IsMsgType", Code: hrEInvalidArg}
	}
	var res C.int32_t
	rc := C.cp_msg_is_type(bytesPtr(msg), C.size_t(len(msg)), C.uint32_t(t), &res)
	runtime.KeepAlive(msg)
	if err := hrErr("IsMsgType", rc); err != nil {
		return false, err
	}
	return res != 0, nil
}

// GetMsgType returns the strongest CAdES type of signer 0 of the CMS msg:
// CadesA, CadesXLongType1, CadesT, CadesBES or CadesPKCS7, checked in that
// order like CadesSignedData.GetMsgType. A message of none of these types
// yields E_INVALIDARG.
func GetMsgType(msg []byte) (CadesType, error) {
	if len(msg) == 0 {
		return 0, &Error{Op: "GetMsgType", Code: hrEInvalidArg}
	}
	var t C.uint32_t
	rc := C.cp_msg_get_type(bytesPtr(msg), C.size_t(len(msg)), &t)
	runtime.KeepAlive(msg)
	if err := hrErr("GetMsgType", rc); err != nil {
		return 0, err
	}
	return CadesType(t), nil
}

// IsMsgType is the package-level IsMsgType, as CadesSignedData.IsMsgType.
func (s *SignedData) IsMsgType(msg []byte, t CadesType) (bool, error) { return IsMsgType(msg, t) }

// GetMsgType is the package-level GetMsgType, as CadesSignedData.GetMsgType.
func (s *SignedData) GetMsgType(msg []byte) (CadesType, error) { return GetMsgType(msg) }
