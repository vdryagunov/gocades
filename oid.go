//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import "unsafe"

// OID mirrors CadesOID.
type OID struct {
	// Value is the dotted OID, for example "1.2.643.7.1.1.2.2".
	Value string
	// Name is the display name reported by the CSP, or "" when unknown.
	Name string
}

// NewOID resolves an OID against the CSP object identifier table.
//
// An unknown OID is not an error: Name stays empty and FriendlyName falls back
// to Value.
func NewOID(value string) *OID {
	return &OID{Value: value, Name: oidName(value)}
}

// FriendlyName returns the human readable name, or the OID when unknown.
//
// CryptoAPI exposes a single display name per OID, so it matches Name.
func (o *OID) FriendlyName() string {
	if o.Name != "" {
		return o.Name
	}
	return o.Value
}

// String implements fmt.Stringer.
func (o *OID) String() string { return o.Value }

// oidName looks up the display name of an OID; unknown OIDs yield "".
func oidName(value string) string {
	if value == "" {
		return ""
	}

	coid := C.CString(value)
	defer C.free(unsafe.Pointer(coid))

	var b C.cp_buf
	if C.cp_oid_info(coid, &b) != 0 {
		return ""
	}
	return string(bufToBytes(b))
}
