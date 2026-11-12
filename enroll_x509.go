//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"unsafe"
)

// X509CertificateEnrollmentContext mirrors CAPICOM/CertEnroll context.
type X509CertificateEnrollmentContext int32

const (
	ContextUser                      X509CertificateEnrollmentContext = 0x1
	ContextMachine                   X509CertificateEnrollmentContext = 0x2
	ContextAdministratorForceMachine X509CertificateEnrollmentContext = 0x3
)

// X509KeySpec mirrors XCN_AT_*.
type X509KeySpec uint32

const (
	ATNone        X509KeySpec = 0
	ATKeyExchange X509KeySpec = 1
	ATSignature   X509KeySpec = 2
)

// X509PrivateKey mirrors CPPEnrollX509PrivateKey for the PKCS#10 path.
type X509PrivateKey struct {
	ProviderName  string
	ProviderType  uint32
	ContainerName string
	UniqueName    string
	KeySpec       X509KeySpec
	Existing      bool
	Exportable    bool
	Silent        bool
	Pin           string
	ready         bool
}

func (k *X509PrivateKey) provType() uint32 {
	if k != nil && k.ProviderType != 0 {
		return k.ProviderType
	}
	return ProvGOST2012_256
}

func (k *X509PrivateKey) keySpec() uint32 {
	if k != nil && k.KeySpec != 0 {
		return uint32(k.KeySpec)
	}
	return uint32(ATKeyExchange)
}

// Create opens a new key container and generates a key pair.
func (k *X509PrivateKey) Create() error {
	if k == nil {
		return &Error{Op: "X509PrivateKey.Create", Code: hrEInvalidArg}
	}
	if k.Existing {
		return fmt.Errorf("gocades: X509PrivateKey.Create: Existing is set; use Open")
	}
	var cProv, cCont, cPin *C.char
	if k.ProviderName != "" {
		cProv = C.CString(k.ProviderName)
		defer C.free(unsafe.Pointer(cProv))
	}
	if k.ContainerName != "" {
		cCont = C.CString(k.ContainerName)
		defer C.free(unsafe.Pointer(cCont))
	}
	if k.Pin != "" {
		cPin = C.CString(k.Pin)
		defer C.free(unsafe.Pointer(cPin))
	}
	var outCont, outUnique *C.char
	rc := C.cp_enroll_create_key(
		cProv, C.uint32_t(k.provType()), cCont, C.uint32_t(k.keySpec()),
		boolToC(k.Exportable), boolToC(k.Silent), cPin, &outCont, &outUnique,
	)
	if outCont != nil {
		k.ContainerName = C.GoString(outCont)
		C.free(unsafe.Pointer(outCont))
	}
	if outUnique != nil {
		k.UniqueName = C.GoString(outUnique)
		C.free(unsafe.Pointer(outUnique))
	}
	if err := hrErr("X509PrivateKey.Create", rc); err != nil {
		return err
	}
	k.ready = true
	return nil
}

// Open attaches to an existing container (no CryptGenKey).
func (k *X509PrivateKey) Open() error {
	if k == nil || k.ContainerName == "" {
		return &Error{Op: "X509PrivateKey.Open", Code: hrEInvalidArg}
	}
	k.Existing = true
	k.ready = true
	return nil
}

// Delete removes the key container (CRYPT_DELETEKEYSET).
func (k *X509PrivateKey) Delete() error {
	if k == nil || k.ContainerName == "" {
		return &Error{Op: "X509PrivateKey.Delete", Code: hrEInvalidArg}
	}
	var cProv, cCont *C.char
	if k.ProviderName != "" {
		cProv = C.CString(k.ProviderName)
		defer C.free(unsafe.Pointer(cProv))
	}
	cCont = C.CString(k.ContainerName)
	defer C.free(unsafe.Pointer(cCont))
	err := hrErr("X509PrivateKey.Delete",
		C.cp_enroll_container_delete(cCont, cProv, C.uint32_t(k.provType()), boolToC(true)))
	if err == nil {
		k.ready = false
	}
	return err
}

// X500DistinguishedName mirrors CPPEnrollX500DistinguishedName.
type X500DistinguishedName struct {
	name string
}

// Encode stores an X.500 distinguished name string (CertStrToName syntax).
func (d *X500DistinguishedName) Encode(name string) error {
	if d == nil || name == "" {
		return &Error{Op: "X500DistinguishedName.Encode", Code: hrEInvalidArg}
	}
	d.name = name
	return nil
}

// Name returns the encoded string.
func (d *X500DistinguishedName) Name() string {
	if d == nil {
		return ""
	}
	return d.name
}

// X509CertificateRequestPkcs10 mirrors CPPEnrollX509CertificateRequestPkcs10.
type X509CertificateRequestPkcs10 struct {
	key      *X509PrivateKey
	subject  *X500DistinguishedName
	context  X509CertificateEnrollmentContext
	signOID  string
	keyUsage uint32
	encoded  []byte
}

// InitializeFromPrivateKey binds a private key, like
// CX509CertificateRequestPkcs10.InitializeFromPrivateKey.
// templateName is accepted for parity and ignored (CryptoPro C path has no
// certificate-template attribute helper here).
func (r *X509CertificateRequestPkcs10) InitializeFromPrivateKey(
	ctx X509CertificateEnrollmentContext, key *X509PrivateKey, _ string,
) error {
	if r == nil || key == nil {
		return &Error{Op: "X509CertificateRequestPkcs10.InitializeFromPrivateKey", Code: hrEInvalidArg}
	}
	switch ctx {
	case ContextUser, ContextMachine, ContextAdministratorForceMachine:
	default:
		return &Error{Op: "X509CertificateRequestPkcs10.InitializeFromPrivateKey", Code: hrEInvalidArg}
	}
	if ctx != ContextUser {
		// Machine store context is not wired yet; keys still live in the
		// provider container selected by the caller.
	}
	if !key.ready {
		if key.Existing {
			if err := key.Open(); err != nil {
				return err
			}
		} else if err := key.Create(); err != nil {
			return err
		}
	}
	r.key = key
	r.context = ctx
	return nil
}

// SetSubject sets the PKCS#10 subject DN.
func (r *X509CertificateRequestPkcs10) SetSubject(dn *X500DistinguishedName) error {
	if r == nil || dn == nil || dn.name == "" {
		return &Error{Op: "X509CertificateRequestPkcs10.SetSubject", Code: hrEInvalidArg}
	}
	r.subject = dn
	return nil
}

// Subject returns the current subject.
func (r *X509CertificateRequestPkcs10) Subject() *X500DistinguishedName { return r.subject }

// PrivateKey returns the bound key.
func (r *X509CertificateRequestPkcs10) PrivateKey() *X509PrivateKey {
	if r == nil {
		return nil
	}
	return r.key
}

// SetKeyUsage adds a KeyUsage extension to the request (0 clears it).
func (r *X509CertificateRequestPkcs10) SetKeyUsage(bits KeyUsageBits) {
	if r != nil {
		r.keyUsage = uint32(bits)
	}
}

// SetHashAlgorithmOID overrides the signature OID (empty → CSP default).
func (r *X509CertificateRequestPkcs10) SetHashAlgorithmOID(oid string) {
	if r != nil {
		r.signOID = oid
	}
}

// Encode builds the DER PKCS#10 request.
func (r *X509CertificateRequestPkcs10) Encode() ([]byte, error) {
	if r == nil || r.key == nil || r.key.ContainerName == "" || r.subject == nil || r.subject.name == "" {
		return nil, &Error{Op: "X509CertificateRequestPkcs10.Encode", Code: hrEInvalidArg}
	}
	var cProv, cCont, cPin, cSubj, cOID *C.char
	if r.key.ProviderName != "" {
		cProv = C.CString(r.key.ProviderName)
		defer C.free(unsafe.Pointer(cProv))
	}
	cCont = C.CString(r.key.ContainerName)
	defer C.free(unsafe.Pointer(cCont))
	if r.key.Pin != "" {
		cPin = C.CString(r.key.Pin)
		defer C.free(unsafe.Pointer(cPin))
	}
	cSubj = C.CString(r.subject.name)
	defer C.free(unsafe.Pointer(cSubj))
	if r.signOID != "" {
		cOID = C.CString(r.signOID)
		defer C.free(unsafe.Pointer(cOID))
	}
	params := C.cp_enroll_pkcs10_params{
		prov_name: cProv,
		prov_type: C.uint32_t(r.key.provType()),
		container: cCont,
		key_spec:  C.uint32_t(r.key.keySpec()),
		silent:    boolToC(r.key.Silent),
		pin:       cPin,
		subject:   cSubj,
		sign_oid:  cOID,
		key_usage: C.uint32_t(r.keyUsage),
	}
	var buf C.cp_buf
	if err := hrErr("X509CertificateRequestPkcs10.Encode",
		C.cp_enroll_create_pkcs10(&params, &buf)); err != nil {
		return nil, err
	}
	der := bufToBytes(buf)
	r.encoded = der
	return der, nil
}

// X509Enrollment mirrors CPPEnrollX509Enrollment.
type X509Enrollment struct {
	req                    *X509CertificateRequestPkcs10
	FriendlyName           string
	CertificateDescription string
	Silent                 bool
}

// InitializeFromRequest prepares enrollment from a PKCS#10 request object.
func (e *X509Enrollment) InitializeFromRequest(req *X509CertificateRequestPkcs10) error {
	if e == nil || req == nil || req.key == nil {
		return &Error{Op: "X509Enrollment.InitializeFromRequest", Code: hrEInvalidArg}
	}
	e.req = req
	if e.Silent {
		req.key.Silent = true
	}
	return nil
}

// CreateRequest returns the PKCS#10 in the requested encoding
// (EncodingBase64 / EncodingBinary / EncodingAny→base64).
func (e *X509Enrollment) CreateRequest(enc EncodingType) (string, error) {
	if e == nil || e.req == nil {
		return "", &Error{Op: "X509Enrollment.CreateRequest", Code: hrEInvalidArg}
	}
	der := e.req.encoded
	if der == nil {
		var err error
		der, err = e.req.Encode()
		if err != nil {
			return "", err
		}
	}
	ed := NewEncodedData(der)
	switch enc {
	case EncodingBinary:
		return ed.Format(EncodingBinary)
	case EncodingBase64, EncodingAny:
		return ed.Format(EncodingBase64)
	default:
		return "", fmt.Errorf("gocades: unsupported encoding type")
	}
}

// CreateRequestDER returns the raw DER PKCS#10.
func (e *X509Enrollment) CreateRequestDER() ([]byte, error) {
	s, err := e.CreateRequest(EncodingBinary)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// InstallResponseRestrictionFlags mirrors CADESCOM_InstallResponseRestrictionFlags.
type InstallResponseRestrictionFlags int32

const (
	AllowNone                 InstallResponseRestrictionFlags = 0
	AllowNoOutstandingRequest InstallResponseRestrictionFlags = 0x1
	AllowUntrustedCertificate InstallResponseRestrictionFlags = 0x2
	AllowUntrustedRoot        InstallResponseRestrictionFlags = 0x4
)

// InstallResponse installs an issued certificate and binds it to the request key.
// response is DER or base64 (per enc). store may be nil → CurrentUser/My.
func (e *X509Enrollment) InstallResponse(
	_ InstallResponseRestrictionFlags, response string, enc EncodingType, _ string, store *Store,
) error {
	if e == nil || e.req == nil || e.req.key == nil || response == "" {
		return &Error{Op: "X509Enrollment.InstallResponse", Code: hrEInvalidArg}
	}
	raw, err := decodeEncodedData(response, enc)
	if err != nil {
		return err
	}
	if enc == EncodingBinary || enc == EncodingAny {
		if b64, perr := pemLikeBase64(response); perr == nil {
			raw = b64
		}
	}
	k := e.req.key
	var cProv, cCont, cPin *C.char
	if k.ProviderName != "" {
		cProv = C.CString(k.ProviderName)
		defer C.free(unsafe.Pointer(cProv))
	}
	cCont = C.CString(k.ContainerName)
	defer C.free(unsafe.Pointer(cCont))
	if k.Pin != "" {
		cPin = C.CString(k.Pin)
		defer C.free(unsafe.Pointer(cPin))
	}
	var hStore unsafe.Pointer
	if store != nil {
		h, err := optionalStoreHandle(store)
		if err != nil {
			return err
		}
		hStore = h
		defer runtime.KeepAlive(store)
	}
	rc := C.cp_enroll_install_cert(
		cProv, C.uint32_t(k.provType()), cCont, C.uint32_t(k.keySpec()),
		boolToC(k.Silent || e.Silent), cPin,
		bytesPtr(raw), C.size_t(len(raw)), hStore,
	)
	return hrErr("X509Enrollment.InstallResponse", rc)
}

func pemLikeBase64(s string) ([]byte, error) {
	if !strings.Contains(s, "-----BEGIN") {
		return nil, fmt.Errorf("not pem")
	}
	var body strings.Builder
	in := false
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.HasPrefix(ln, "-----") {
			if in {
				break
			}
			in = true
			continue
		}
		if in {
			body.WriteString(ln)
		}
	}
	if body.Len() == 0 {
		return nil, fmt.Errorf("bad pem")
	}
	return base64.StdEncoding.DecodeString(body.String())
}
