//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// SignedData mirrors CadesSignedData.
//
// The signing methods return the CMS directly, the idiomatic Go shape. The
// object also remembers the last CMS it produced or verified, as CAdESCOM
// does, for Certificates.
type SignedData struct {
	content    []byte
	encoding   EncodingType
	signers    Signers
	additional *Store
	tsaURL     string
	checkCert  bool
	hashOID    string
	include    CertIncludeOption
	authAttrs  Attributes
	unauthAttrs Attributes
	message    []byte
}

// NewSignedData returns an empty SignedData, like pycades.SignedData().
func NewSignedData() *SignedData {
	return &SignedData{encoding: EncodingBase64, checkCert: true}
}

// SetContent sets the content to sign or verify.
func (s *SignedData) SetContent(content []byte) { s.content = content }

// Content returns the content set on the object.
func (s *SignedData) Content() []byte { return s.content }

// SetContentEncoding mirrors CadesSignedData.ContentEncoding.
//
// The value is recorded for API parity; this port always works with raw bytes,
// so the encoding has no effect on signing.
func (s *SignedData) SetContentEncoding(t EncodingType) { s.encoding = t }

// ContentEncoding returns the configured content encoding.
func (s *SignedData) ContentEncoding() EncodingType { return s.encoding }

// Signers returns the signers of the last verification, one per signer of the
// CMS, invalid ones included. Their certificates belong to the SignedData and
// stay valid until the next verification or Close.
func (s *SignedData) Signers() Signers { return s.signers }

// Certificates returns every certificate carried by the CMS last signed or
// verified with this object, like CadesSignedData.Certificates; see
// MessageCertificates. It returns nil before the first signing or
// verification. The caller owns the certificates.
func (s *SignedData) Certificates() ([]*Certificate, error) {
	if s.message == nil {
		return nil, nil
	}
	return MessageCertificates(s.message)
}

// AdditionalStore registers an extra store, like
// CadesSignedData.AdditionalStore. Verification searches it for certificates
// and CRLs; signing with a chain option searches it for intermediate
// certificates.
func (s *SignedData) AdditionalStore(st *Store) { s.additional = st }

// SetOptions selects the certificates embedded by the signing methods, like
// CadesSigner.Options. The default is IncludeChainExceptRoot.
func (s *SignedData) SetOptions(o CertIncludeOption) { s.include = o }

// Options returns the certificate include option.
func (s *SignedData) Options() CertIncludeOption { return s.include }

// SetTSAAddress sets the timestamp authority used when the CAdES type requires
// a timestamp, like CadesSignedData.Signers -> TSAAddress.
func (s *SignedData) SetTSAAddress(url string) { s.tsaURL = url }

// TSAAddress returns the configured timestamp authority.
func (s *SignedData) TSAAddress() string { return s.tsaURL }

// SetCheckCertificate mirrors CadesSigner.CheckCertificate. When true (the
// default), CAdES signing sets CADES_CHECK_CERT_REQ so CadesSignMessage
// validates the signer certificate.
func (s *SignedData) SetCheckCertificate(v bool) { s.checkCert = v }

// CheckCertificate reports whether the signer certificate is checked before
// CAdES signing.
func (s *SignedData) CheckCertificate() bool { return s.checkCert }

// AuthenticatedAttributes returns the signed attributes added to the next
// signature, like CadesSigner.AuthenticatedAttributes. Mutate with Add,
// Clear and Remove.
func (s *SignedData) AuthenticatedAttributes() *Attributes { return &s.authAttrs }

// UnauthenticatedAttributes returns the unsigned attributes added to the next
// signature, like CadesSigner.UnauthenticatedAttributes.
func (s *SignedData) UnauthenticatedAttributes() *Attributes { return &s.unauthAttrs }

// SetHashAlgorithm overrides the digest OID. Empty means GOST R 34.11-2012 256.
func (s *SignedData) SetHashAlgorithm(oid string) { s.hashOID = oid }

// signArgs prepares C attribute lists for a signing call. The caller must
// defer free on both lists.
func (s *SignedData) signArgs() (check C.int32_t, auth, unauth *cAttrList) {
	if s.checkCert {
		check = 1
	}
	auth = attributesToC(s.authAttrs)
	unauth = attributesToC(s.unauthAttrs)
	return check, auth, unauth
}

// Close releases the certificates held by the object.
func (s *SignedData) Close() {
	s.signers.Close()
	s.signers = Signers{}
	s.message = nil
}

// signing returns the handles of a signing call: the certificate and the
// optional chain store. The caller keeps cert and s.additional alive.
func (s *SignedData) signing(cert *Certificate) (unsafe.Pointer, unsafe.Pointer, error) {
	h, err := cert.handle()
	if err != nil {
		return nil, nil, err
	}
	hs, err := optionalStoreHandle(s.additional)
	if err != nil {
		return nil, nil, err
	}
	return h, hs, nil
}

// signed records the CMS produced by a signing call.
func (s *SignedData) signed(op string, rc C.int32_t, out C.cp_buf) ([]byte, error) {
	if rc != 0 {
		return nil, hrErr(op, rc)
	}
	sig := bufToBytes(out)
	s.message = bytes.Clone(sig)
	return sig, nil
}

// SignCades produces a CAdES signature over the object content, like
// CadesSignedData.SignCades.
func (s *SignedData) SignCades(cert *Certificate, typ CadesType, detached bool) ([]byte, error) {
	h, hs, err := s.signing(cert)
	if err != nil {
		return nil, err
	}

	coid, ctsa, cleanup := s.cStrings()
	defer cleanup()
	check, auth, unauth := s.signArgs()
	defer auth.free()
	defer unauth.free()

	var out C.cp_buf
	rc := C.cp_sign_cades(h, C.int32_t(s.include), hs, check, auth.list, unauth.list,
		C.int32_t(typ), coid, ctsa, bytesPtr(s.content), C.size_t(len(s.content)),
		boolToC(detached), &out)
	runtime.KeepAlive(cert)
	runtime.KeepAlive(s.additional)
	runtime.KeepAlive(auth)
	runtime.KeepAlive(unauth)
	return s.signed("SignedData.SignCades", rc, out)
}

// SignHash produces a CAdES signature over a precomputed digest, like
// CadesSignedData.SignHash. The digest must use s.hashOID.
func (s *SignedData) SignHash(cert *Certificate, digest []byte, typ CadesType) ([]byte, error) {
	h, hs, err := s.signing(cert)
	if err != nil {
		return nil, err
	}

	coid, ctsa, cleanup := s.cStrings()
	defer cleanup()
	check, auth, unauth := s.signArgs()
	defer auth.free()
	defer unauth.free()

	var out C.cp_buf
	rc := C.cp_sign_hash(h, C.int32_t(s.include), hs, check, auth.list, unauth.list,
		C.int32_t(typ), coid, ctsa, bytesPtr(digest), C.size_t(len(digest)), &out)
	runtime.KeepAlive(cert)
	runtime.KeepAlive(s.additional)
	runtime.KeepAlive(auth)
	runtime.KeepAlive(unauth)
	return s.signed("SignedData.SignHash", rc, out)
}

// Sign produces a plain CMS signature (CryptoAPI message layer, no CAdES type)
// with the digest selected by SetHashAlgorithm, like CadesSignedData.Sign.
// CryptoPro still adds contentType, messageDigest, signingTime and
// signingCertificateV2 to the signed attributes.
func (s *SignedData) Sign(cert *Certificate, detached bool) ([]byte, error) {
	h, hs, err := s.signing(cert)
	if err != nil {
		return nil, err
	}

	coid := C.CString(s.hashOIDOrDefault())
	defer C.free(unsafe.Pointer(coid))
	_, auth, unauth := s.signArgs()
	defer auth.free()
	defer unauth.free()

	var out C.cp_buf
	rc := C.cp_sign_cms(h, C.int32_t(s.include), hs, auth.list, unauth.list, coid,
		boolToC(detached), bytesPtr(s.content), C.size_t(len(s.content)), &out)
	runtime.KeepAlive(cert)
	runtime.KeepAlive(s.additional)
	runtime.KeepAlive(auth)
	runtime.KeepAlive(unauth)
	return s.signed("SignedData.Sign", rc, out)
}

// CoSignHash adds a second signature over digest to an existing detached CMS,
// like CadesSignedData.CoSignHash.
func (s *SignedData) CoSignHash(cert *Certificate, sig, digest []byte, typ CadesType) ([]byte, error) {
	h, hs, err := s.signing(cert)
	if err != nil {
		return nil, err
	}

	coid, ctsa, cleanup := s.cStrings()
	defer cleanup()
	check, auth, unauth := s.signArgs()
	defer auth.free()
	defer unauth.free()

	var out C.cp_buf
	rc := C.cp_cosign_hash(h, C.int32_t(s.include), hs, check, auth.list, unauth.list,
		C.int32_t(typ), coid, ctsa, bytesPtr(sig), C.size_t(len(sig)),
		bytesPtr(digest), C.size_t(len(digest)), &out)
	runtime.KeepAlive(cert)
	runtime.KeepAlive(s.additional)
	runtime.KeepAlive(auth)
	runtime.KeepAlive(unauth)
	return s.signed("SignedData.CoSignHash", rc, out)
}

// CoSignCades adds a second CAdES signature over the object content to an
// existing detached CMS, like CadesSignedData.CoSignCades.
//
// The content digest is computed with the algorithm selected by
// SetHashAlgorithm, so it matches the signature being extended.
func (s *SignedData) CoSignCades(cert *Certificate, sig []byte, typ CadesType) ([]byte, error) {
	if _, err := cert.handle(); err != nil {
		return nil, err
	}
	digest, err := s.contentDigest()
	if err != nil {
		return nil, err
	}
	return s.CoSignHash(cert, sig, digest, typ)
}

// CoSign adds a plain CMS signature (CryptoAPI message layer, no CAdES type)
// over the object content, like CadesSignedData.CoSign.
//
// With content set, sig is a detached signature over it; without content, sig
// is an attached signature that carries its content. CryptoPro itself puts
// contentType, messageDigest, signingTime and signingCertificateV2 into the
// signed attributes, as it does for Sign.
func (s *SignedData) CoSign(cert *Certificate, sig []byte) ([]byte, error) {
	h, hs, err := s.signing(cert)
	if err != nil {
		return nil, err
	}

	coid := C.CString(s.hashOIDOrDefault())
	defer C.free(unsafe.Pointer(coid))
	_, auth, unauth := s.signArgs()
	defer auth.free()
	defer unauth.free()

	detached := len(s.content) > 0
	var out C.cp_buf
	rc := C.cp_cosign_cms(h, C.int32_t(s.include), hs, auth.list, unauth.list, coid,
		bytesPtr(sig), C.size_t(len(sig)), boolToC(detached),
		bytesPtr(s.content), C.size_t(len(s.content)), &out)
	runtime.KeepAlive(cert)
	runtime.KeepAlive(s.additional)
	runtime.KeepAlive(auth)
	runtime.KeepAlive(unauth)
	return s.signed("SignedData.CoSign", rc, out)
}

// VerifyCades verifies every signer of a CAdES signature, like
// CadesSignedData.VerifyCades, and replaces Signers with the per-signer
// results.
//
// It returns the information of signer 0 and, when any signer fails, a
// *VerifyError for the first failing one; the information is returned in
// that case too, and the caller owns its SignerCertificate either way.
func (s *SignedData) VerifyCades(sig []byte, typ CadesType, detached bool) (VerificationInfo, error) {
	return s.verifySigners(sig, func(i int) (VerificationInfo, error) {
		return verifyMessageInfo("SignedData.VerifyCades", sig, s.content, typ, detached, s.additional, i)
	})
}

// Verify verifies a plain CMS signature, like CadesSignedData.Verify, with the
// same contract as VerifyCades. The check runs with CadesPKCS7: CadesDefault
// would demand CAdES-X Long Type 1 evidence.
func (s *SignedData) Verify(sig []byte, detached bool) (VerificationInfo, error) {
	return s.verifySigners(sig, func(i int) (VerificationInfo, error) {
		return verifyMessageInfo("SignedData.Verify", sig, s.content, CadesPKCS7, detached, s.additional, i)
	})
}

// VerifyHash verifies a signature against a precomputed digest, like
// CadesSignedData.VerifyHash, with the same contract as VerifyCades.
func (s *SignedData) VerifyHash(sig, digest []byte, typ CadesType) (VerificationInfo, error) {
	return s.verifySigners(sig, func(i int) (VerificationInfo, error) {
		return verifyHashInfo("SignedData.VerifyHash", sig, digest, typ, s.hashOID, s.additional, i)
	})
}

// EnhanceCades adds timestamp and revocation information to a signature, like
// CadesSignedData.EnhanceCades.
func (s *SignedData) EnhanceCades(sig []byte, typ CadesType) ([]byte, error) {
	out, err := Enhance(sig, typ, s.tsaURL)
	if err != nil {
		return nil, err
	}
	s.message = bytes.Clone(out)
	return out, nil
}

// maxProbedSigners bounds the signer enumeration of a CMS that
// ParseCMSSignerInfos cannot read.
const maxProbedSigners = 1024

// verifySigners runs verify once for every signer of sig and replaces Signers
// with the results, closing the previous ones. It returns the information of
// signer 0 and the first *VerifyError; any other error aborts the run.
func (s *SignedData) verifySigners(sig []byte, verify func(i int) (VerificationInfo, error)) (VerificationInfo, error) {
	// cades.h has no signer count or attribute accessor, so both are read
	// from the encoding. When it does not parse, signers are verified until
	// CAdES reports that there is none, or fails without signer info: a CMS
	// the parser cannot read must not hide a bad signer behind signer 0.
	infos, perr := ParseCMSSignerInfos(sig)
	count := len(infos)
	probe := perr != nil || count == 0
	if probe {
		count = maxProbedSigners
	}

	var first VerificationInfo
	var firstErr error
	list := make([]Signer, 0, len(infos))
	for i := 0; i < count; i++ {
		info, err := verify(i)
		var ve *VerifyError
		if probe && i > 0 && errors.As(err, &ve) &&
			(ve.Code == hrCryptENoSigner || ve.Status == VerifyFailed) {
			info.Close()
			break
		}
		if err != nil && !errors.As(err, &ve) {
			info.Close()
			first.Close()
			Signers{items: list}.Close()
			return VerificationInfo{}, err
		}

		sg := Signer{
			Certificate:            info.SignerCertificate,
			SigningTime:            info.SigningTime,
			SignatureTimeStampTime: info.SignatureTimeStampTime,
			SignatureStatus:        SignatureStatus{IsValid: info.Valid, Status: info.Status, Err: err},
			TSAAddress:             s.tsaURL,
			CheckCertificate:       s.checkCert,
		}
		if i == 0 {
			// The caller owns the returned info; Signers get their own copy.
			first = info
			sg.Certificate = info.SignerCertificate.dup()
		}
		if perr == nil && i < len(infos) {
			sg.AuthenticatedAttributes = namedAttributes(infos[i].SignedAttributes)
			sg.UnauthenticatedAttributes = namedAttributes(infos[i].UnsignedAttributes)
		}
		// Evidence is reported for invalid signers too; a CMS that does not
		// decode has none to report.
		if crls, ocsps, err := revocationValues(sig, i); err == nil {
			sg.CRLs, sg.OCSPResponses = crls, ocsps
		}
		list = append(list, sg)

		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	s.signers.Close()
	s.signers = Signers{items: list}
	s.message = bytes.Clone(sig)
	return first, firstErr
}

// namedAttributes fills in the display names of the attribute OIDs.
func namedAttributes(a Attributes) Attributes {
	for i := range a.items {
		if a.items[i].Name == "" {
			a.items[i].Name = oidName(a.items[i].OID)
		}
	}
	return a
}

// contentDigest hashes the object content with the configured algorithm.
func (s *SignedData) contentDigest() ([]byte, error) {
	if len(s.content) == 0 {
		return nil, &Error{Op: "SignedData.CoSignCades", Code: hrEInvalidArg}
	}

	alg, err := hashAlgForOID(s.hashOID)
	if err != nil {
		return nil, err
	}
	return digest(alg, s.content)
}

// hashAlgForOID maps a digest OID to the CAPICOM hash algorithm. An empty OID
// means the default, GOST R 34.11-2012 (256 bit), as in the signing calls.
func hashAlgForOID(oid string) (HashAlg, error) {
	switch oid {
	case "", "1.2.643.7.1.1.2.2":
		return HashAlgGOST3411_2012_256, nil
	case "1.2.643.7.1.1.2.3":
		return HashAlgGOST3411_2012_512, nil
	case "1.2.643.2.2.9":
		return HashAlgGOST3411, nil
	case "2.16.840.1.101.3.4.2.1":
		return HashAlgSHA256, nil
	case "2.16.840.1.101.3.4.2.2":
		return HashAlgSHA384, nil
	case "2.16.840.1.101.3.4.2.3":
		return HashAlgSHA512, nil
	case "1.3.14.3.2.26":
		return HashAlgSHA1, nil
	case "1.2.840.113549.2.5":
		return HashAlgMD5, nil
	}
	return 0, fmt.Errorf("gocades: unsupported hash algorithm OID %q", oid)
}

func (s *SignedData) hashOIDOrDefault() string {
	if s.hashOID == "" {
		return HashGOST3411_2012_256
	}
	return s.hashOID
}

// cStrings converts the hash OID and TSA URL to C strings.
func (s *SignedData) cStrings() (*C.char, *C.char, func()) {
	coid := C.CString(s.hashOIDOrDefault())

	var ctsa *C.char
	if s.tsaURL != "" {
		ctsa = C.CString(s.tsaURL)
	}

	return coid, ctsa, func() {
		C.free(unsafe.Pointer(coid))
		if ctsa != nil {
			C.free(unsafe.Pointer(ctsa))
		}
	}
}
