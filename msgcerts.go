//go:build (linux || darwin) && cgo

package gocades

/*
#include "gocades.h"
*/
import "C"

import (
	"bytes"
	"unsafe"
)

// MessageCertificates returns every certificate a CMS carries, the way
// CadesSignedData.Certificates collects them: the certificates field, the
// certificate-values attribute of each signer (CAdES-X Long Type 1) and the
// TSA certificates of the signature, CAdES-C and archive timestamps.
// Duplicates are dropped. sig is DER, attached or detached; nothing is
// verified. The caller owns the certificates.
func MessageCertificates(sig []byte) ([]*Certificate, error) {
	if len(sig) == 0 {
		return nil, &Error{Op: "MessageCertificates", Code: hrEInvalidArg}
	}
	var l C.cp_buf_list
	if err := hrErr("MessageCertificates",
		C.cp_msg_certificates(bytesPtr(sig), C.size_t(len(sig)), &l)); err != nil {
		return nil, err
	}

	var out []*Certificate
	var seen [][]byte
	for _, der := range bufListToGo(l) {
		dup := false
		for _, s := range seen {
			if bytes.Equal(s, der) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		c, err := ImportCertificateDER(der)
		if err != nil {
			for _, c := range out {
				c.Close()
			}
			return nil, err
		}
		seen = append(seen, der)
		out = append(out, c)
	}
	return out, nil
}

// revocationValues returns the CRLs and OCSP responses of the
// revocation-values attribute of signer i.
func revocationValues(sig []byte, i int) (Blobs, Blobs, error) {
	var crls, ocsps C.cp_buf_list
	if err := hrErr("revocationValues",
		C.cp_msg_revocation_values(bytesPtr(sig), C.size_t(len(sig)), C.uint32_t(i),
			&crls, &ocsps)); err != nil {
		return Blobs{}, Blobs{}, err
	}
	return Blobs{items: bufListToGo(crls)}, Blobs{items: bufListToGo(ocsps)}, nil
}

// bufListToGo copies a C buffer list into Go and frees it.
func bufListToGo(l C.cp_buf_list) [][]byte {
	defer C.cp_buf_list_free(l)
	if l.len == 0 {
		return nil
	}
	items := unsafe.Slice(l.items, int(l.len))
	out := make([][]byte, len(items))
	for i, b := range items {
		out[i] = C.GoBytes(unsafe.Pointer(b.data), C.int(b.len))
	}
	return out
}
