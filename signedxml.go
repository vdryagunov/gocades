//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"runtime"
	"time"
	"unsafe"
)

// XAdESType mirrors CADESCOM_XADES_TYPE, the profile written into
// XADES_SIGN_PARA.dwSignatureType.
type XAdESType int32

const (
	XAdESXMLDSig    XAdESType = 0x00000000
	XAdESDefault    XAdESType = 0x00000010
	XAdESBES        XAdESType = 0x00000020
	XAdEST          XAdESType = 0x00000050
	XAdESXLongType1 XAdESType = 0x000005D0
	XAdES_A         XAdESType = 0x000007D0
)

func (t XAdESType) String() string {
	switch t {
	case XAdESXMLDSig:
		return "XMLDSIG"
	case XAdESDefault:
		return "DEFAULT"
	case XAdESBES:
		return "BES"
	case XAdEST:
		return "T"
	case XAdESXLongType1:
		return "X_LONG_TYPE_1"
	case XAdES_A:
		return "A"
	}
	return "UNKNOWN"
}

// XMLVerificationInfo describes one verified XML signature.
type XMLVerificationInfo struct {
	// Status is the XADES_VERIFY_* status code; VerifySuccess (0) is valid.
	Status int32
	// Valid reports whether Status is VerifySuccess.
	Valid bool
	// VerifiedXAdESType is the profile actually found in the signature.
	VerifiedXAdESType XAdESType
	// SignerCertificate is the signer certificate taken from the signature.
	SignerCertificate *Certificate
	// SigningTime is the CMS signingTime attribute; zero when absent.
	SigningTime time.Time
	// SignatureTimeStampTime is the TSA time of the signature timestamp.
	SignatureTimeStampTime time.Time
	// SigAndRefsTimeStampTime is the SigAndRefs timestamp time (XAdES-C).
	SigAndRefsTimeStampTime time.Time
}

// Close releases the signer certificate.
func (v *XMLVerificationInfo) Close() {
	if v.SignerCertificate != nil {
		v.SignerCertificate.Close()
		v.SignerCertificate = nil
	}
}

// SignedXML mirrors CadesSignedXML.
type SignedXML struct {
	content         []byte
	xadesType       XAdESType
	digestMethod    string
	signatureMethod string
	xpath           string
	tsaURL          string
	store           *Store
	signers         Signers
}

// NewSignedXML returns an object defaulting to the XAdES default profile.
func NewSignedXML() *SignedXML {
	return &SignedXML{xadesType: XAdESDefault}
}

// SetContent sets the XML document to sign, like CadesSignedXML.Content.
func (s *SignedXML) SetContent(content []byte) { s.content = content }

// Content returns the XML document to sign.
func (s *SignedXML) Content() []byte { return s.content }

// SetSignatureType selects the XAdES profile, like the pycades SignatureType
// property.
//
// pycades types it as CADESCOM_XML_SIGNATURE_TYPE (enveloped / enveloping /
// template), but the C field XADES_SIGN_PARA.dwSignatureType carries the
// profile (XADES_BES, ...); the enveloped/enveloping form is inferred from the
// document and the XPath.
func (s *SignedXML) SetSignatureType(t XAdESType) { s.xadesType = t }

// SignatureType returns the selected XAdES profile.
func (s *SignedXML) SignatureType() XAdESType { return s.xadesType }

// SetDigestMethod overrides the digest algorithm URI, like
// CadesSignedXML.DigestMethod.
func (s *SignedXML) SetDigestMethod(uri string) { s.digestMethod = uri }

// DigestMethod returns the configured digest algorithm URI.
func (s *SignedXML) DigestMethod() string { return s.digestMethod }

// SetSignatureMethod overrides the signature algorithm URI.
func (s *SignedXML) SetSignatureMethod(uri string) { s.signatureMethod = uri }

// SignatureMethod returns the configured signature algorithm URI.
func (s *SignedXML) SignatureMethod() string { return s.signatureMethod }

// SetXPath sets the XPath expression selecting the node to sign.
func (s *SignedXML) SetXPath(expr string) { s.xpath = expr }

// XPath returns the configured XPath expression.
func (s *SignedXML) XPath() string { return s.xpath }

// SetTSAAddress sets the timestamp authority for XAdES-T and above.
func (s *SignedXML) SetTSAAddress(url string) { s.tsaURL = url }

// SetStore sets the store used to build the certificate chain during
// verification.
func (s *SignedXML) SetStore(st *Store) { s.store = st }

// Signers returns the signers extracted by the last verification.
func (s *SignedXML) Signers() Signers { return s.signers }

// Sign embeds a signature into Content and returns the signed XML, like
// CadesSignedXML.Sign.
func (s *SignedXML) Sign(cert *Certificate) ([]byte, error) {
	return s.sign(cert, false)
}

// SignDetached produces a detached XML signature over Content.
func (s *SignedXML) SignDetached(cert *Certificate) ([]byte, error) {
	return s.sign(cert, true)
}

func (s *SignedXML) sign(cert *Certificate, detached bool) ([]byte, error) {
	h, err := cert.handle()
	if err != nil {
		return nil, err
	}

	cxpath := C.CString(s.xpath)
	defer C.free(unsafe.Pointer(cxpath))
	cdigest := C.CString(s.digestMethod)
	defer C.free(unsafe.Pointer(cdigest))
	csig := C.CString(s.signatureMethod)
	defer C.free(unsafe.Pointer(csig))

	var ctsa *C.char
	if s.tsaURL != "" {
		ctsa = C.CString(s.tsaURL)
		defer C.free(unsafe.Pointer(ctsa))
	}

	var out C.cp_buf
	rc := C.cp_xades_sign(h, C.int32_t(s.xadesType), cdigest, csig, ctsa,
		cxpath, bytesPtr(s.content), C.size_t(len(s.content)),
		boolToC(detached), &out)
	runtime.KeepAlive(cert)

	if rc != 0 {
		return nil, hrErr("SignedXML.Sign", rc)
	}
	return bufToBytes(out), nil
}

// Verify checks the XML signatures of signed, like CadesSignedXML.Verify, and
// replaces Signers with the per-signature results.
//
// When any signature fails it returns a *VerifyError for the first failing
// one together with the information of all signatures; the caller owns their
// SignerCertificate either way. Signers hold independent copies.
func (s *SignedXML) Verify(signed []byte) ([]XMLVerificationInfo, error) {
	const op = "SignedXML.Verify"

	cxpath := C.CString(s.xpath)
	defer C.free(unsafe.Pointer(cxpath))

	hStore, err := optionalStoreHandle(s.store)
	if err != nil {
		return nil, err
	}

	var arr C.cp_xades_info_array
	rc := C.cp_xades_verify(hStore, cxpath,
		bytesPtr(signed), C.size_t(len(signed)), &arr)
	runtime.KeepAlive(s.store)
	defer C.cp_xades_info_array_free(arr)

	items := unsafe.Slice(arr.items, int(arr.len))

	out := make([]XMLVerificationInfo, 0, len(items))
	signers := make([]Signer, 0, len(items))
	var firstErr *VerifyError

	for i := range items {
		it := &items[i]
		status := int32(it.status)
		vErr := verifyErr(op, i, 0, status)
		info := XMLVerificationInfo{
			Status:                  status,
			Valid:                   vErr == nil,
			VerifiedXAdESType:       XAdESType(it.xades_type),
			SigningTime:             unixOrZero(int64(it.signing_time)),
			SignatureTimeStampTime:  unixOrZero(int64(it.signature_ts_time)),
			SigAndRefsTimeStampTime: unixOrZero(int64(it.sig_and_refs_ts_time)),
		}
		if it.signer_cert != nil {
			// Ownership moves to Go; the array free must not release it.
			info.SignerCertificate = newCertificate(unsafe.Pointer(it.signer_cert))
			it.signer_cert = nil
		}
		out = append(out, info)

		signers = append(signers, Signer{
			Certificate:            info.SignerCertificate.dup(),
			SigningTime:            info.SigningTime,
			SignatureTimeStampTime: info.SignatureTimeStampTime,
			SignatureStatus:        SignatureStatus{IsValid: info.Valid, Status: status, Err: vErr},
			TSAAddress:             s.tsaURL,
		})
		if vErr != nil && firstErr == nil {
			firstErr = vErr.(*VerifyError)
		}
	}

	s.signers.Close()
	s.signers = Signers{items: signers}

	if rc != 0 {
		if firstErr == nil {
			return out, verifyErr(op, 0, int32(rc), VerifySuccess)
		}
		firstErr.Code = int32(rc)
	}
	if firstErr != nil {
		return out, firstErr
	}
	return out, nil
}
