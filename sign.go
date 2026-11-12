//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// CertIncludeOption mirrors CAPICOM_CERTIFICATE_INCLUDE_OPTION: which
// certificates a signature embeds in the CMS (CadesSigner.Options).
//
// The chain options build the chain from the system stores and the extra
// store given with the signing call, without revocation checks and without
// network retrieval. Unlike CAdESCOM, which refuses to sign when the chain
// has any trust error, whatever part of the chain could be built is embedded:
// trust is the verifier's decision.
type CertIncludeOption int32

const (
	// IncludeChainExceptRoot embeds the chain without a self-signed root.
	// It is the zero value and the CAdESCOM default.
	IncludeChainExceptRoot CertIncludeOption = 0
	// IncludeWholeChain embeds the chain including the root.
	IncludeWholeChain CertIncludeOption = 1
	// IncludeEndEntityOnly embeds only the signer certificate.
	IncludeEndEntityOnly CertIncludeOption = 2
	// IncludeNone embeds no certificate: verifiers must find the signer
	// certificate elsewhere.
	IncludeNone CertIncludeOption = 0x100
)

// SignOptions configures a detached CAdES signature.
type SignOptions struct {
	// Type is CadesBES, CadesT or CadesXLongType1.
	Type CadesType
	// HashOID overrides the hash algorithm OID. Empty means GOST R 34.11-2012 256.
	HashOID string
	// TSAURL is the timestamp authority URL, used with CadesT / CadesXLongType1.
	TSAURL string
	// Include selects the embedded certificates; the zero value is
	// IncludeChainExceptRoot.
	Include CertIncludeOption
	// ChainStore is an extra store searched for intermediate certificates
	// when Include builds the chain; may be nil.
	ChainStore *Store
	// CheckCertificate enables CADES_CHECK_CERT_REQ. The zero value is false
	// here (unlike SignedData, where the default is true); set it explicitly.
	CheckCertificate bool
	// AuthAttrs are extra signed attributes embedded in the CMS.
	AuthAttrs Attributes
	// UnauthAttrs are extra unsigned attributes embedded in the CMS.
	UnauthAttrs Attributes
}

// cStrings converts the hash OID and TSA URL to C strings.
func (o SignOptions) cStrings() (*C.char, *C.char, func()) {
	oid := o.HashOID
	if oid == "" {
		oid = HashGOST3411_2012_256
	}
	coid := C.CString(oid)

	var ctsa *C.char
	if o.TSAURL != "" {
		ctsa = C.CString(o.TSAURL)
	}

	return coid, ctsa, func() {
		C.free(unsafe.Pointer(coid))
		if ctsa != nil {
			C.free(unsafe.Pointer(ctsa))
		}
	}
}

// SignDetached produces a detached CAdES signature over content.
//
// For PAdES, content is the concatenation of the PDF /ByteRange segments.
func SignDetached(cert *Certificate, content []byte, opts SignOptions) ([]byte, error) {
	h, err := cert.handle()
	if err != nil {
		return nil, err
	}
	hs, err := optionalStoreHandle(opts.ChainStore)
	if err != nil {
		return nil, err
	}

	coid, ctsa, cleanup := opts.cStrings()
	defer cleanup()
	var check C.int32_t
	if opts.CheckCertificate {
		check = 1
	}
	auth := attributesToC(opts.AuthAttrs)
	defer auth.free()
	unauth := attributesToC(opts.UnauthAttrs)
	defer unauth.free()

	var out C.cp_buf
	rc := C.cp_sign_detached(h, C.int32_t(opts.Include), hs, check, auth.list, unauth.list,
		C.int32_t(opts.Type), coid, ctsa, bytesPtr(content), C.size_t(len(content)), &out)
	runtime.KeepAlive(cert)
	runtime.KeepAlive(opts.ChainStore)
	runtime.KeepAlive(auth)
	runtime.KeepAlive(unauth)
	if rc != 0 {
		return nil, hrErr("SignDetached", rc)
	}
	return bufToBytes(out), nil
}

// SignDetachedHash produces a detached CAdES signature over a precomputed
// digest. The digest must be computed with the algorithm identified by
// opts.HashOID (GOST R 34.11-2012 256 by default).
func SignDetachedHash(cert *Certificate, digest []byte, opts SignOptions) ([]byte, error) {
	h, err := cert.handle()
	if err != nil {
		return nil, err
	}
	hs, err := optionalStoreHandle(opts.ChainStore)
	if err != nil {
		return nil, err
	}

	coid, ctsa, cleanup := opts.cStrings()
	defer cleanup()
	var check C.int32_t
	if opts.CheckCertificate {
		check = 1
	}
	auth := attributesToC(opts.AuthAttrs)
	defer auth.free()
	unauth := attributesToC(opts.UnauthAttrs)
	defer unauth.free()

	var out C.cp_buf
	rc := C.cp_sign_hash(h, C.int32_t(opts.Include), hs, check, auth.list, unauth.list,
		C.int32_t(opts.Type), coid, ctsa, bytesPtr(digest), C.size_t(len(digest)), &out)
	runtime.KeepAlive(cert)
	runtime.KeepAlive(opts.ChainStore)
	runtime.KeepAlive(auth)
	runtime.KeepAlive(unauth)
	if rc != 0 {
		return nil, hrErr("SignDetachedHash", rc)
	}
	return bufToBytes(out), nil
}

// VerifyDetached verifies signer 0 of a detached CAdES signature over content.
// A signature that does not verify yields a *VerifyError.
func VerifyDetached(sig, content []byte, typ CadesType) error {
	var status C.int32_t
	rc := C.cp_verify_detached(bytesPtr(sig), C.size_t(len(sig)),
		C.int32_t(typ), bytesPtr(content), C.size_t(len(content)), &status)
	return verifyErr("VerifyDetached", 0, int32(rc), int32(status))
}

// Enhance adds timestamp/revocation information to an existing signature.
func Enhance(sig []byte, typ CadesType, tsaURL string) ([]byte, error) {
	var ctsa *C.char
	if tsaURL != "" {
		ctsa = C.CString(tsaURL)
		defer C.free(unsafe.Pointer(ctsa))
	}

	var out C.cp_buf
	rc := C.cp_enhance(bytesPtr(sig), C.size_t(len(sig)), C.int32_t(typ), ctsa, &out)
	if rc != 0 {
		return nil, hrErr("Enhance", rc)
	}
	return bufToBytes(out), nil
}
