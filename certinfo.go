//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"fmt"
	"math"
	"runtime"
	"time"
	"unsafe"
)

// CertInfoType mirrors CAPICOM_CERT_INFO_TYPE.
type CertInfoType int32

const (
	CertInfoSubjectSimpleName CertInfoType = 0
	CertInfoIssuerSimpleName  CertInfoType = 1
	CertInfoSubjectEmailName  CertInfoType = 2
	CertInfoIssuerEmailName   CertInfoType = 3
	CertInfoSubjectUPN        CertInfoType = 4
	CertInfoIssuerUPN         CertInfoType = 5
	CertInfoSubjectDNSName    CertInfoType = 6
	CertInfoIssuerDNSName     CertInfoType = 7
)

// KeyUsageBits is the KeyUsage extension bitmask. Bit numbering follows the
// X.509 KeyUsage extension, so it matches CadesKeyUsage predicates.
type KeyUsageBits uint32

const (
	KeyUsageDigitalSignature KeyUsageBits = 1 << 0
	KeyUsageNonRepudiation   KeyUsageBits = 1 << 1
	KeyUsageKeyEncipherment  KeyUsageBits = 1 << 2
	KeyUsageDataEncipherment KeyUsageBits = 1 << 3
	KeyUsageKeyAgreement     KeyUsageBits = 1 << 4
	KeyUsageKeyCertSign      KeyUsageBits = 1 << 5
	KeyUsageCRLSign          KeyUsageBits = 1 << 6
	KeyUsageEncipherOnly     KeyUsageBits = 1 << 7
	KeyUsageDecipherOnly     KeyUsageBits = 1 << 8
)

// KeyUsage mirrors CadesKeyUsage.
type KeyUsage struct {
	Present  bool
	Critical bool
	Bits     KeyUsageBits
}

func (k KeyUsage) IsDigitalSignatureEnabled() bool { return k.Bits&KeyUsageDigitalSignature != 0 }
func (k KeyUsage) IsNonRepudiationEnabled() bool   { return k.Bits&KeyUsageNonRepudiation != 0 }
func (k KeyUsage) IsKeyEnciphermentEnabled() bool  { return k.Bits&KeyUsageKeyEncipherment != 0 }
func (k KeyUsage) IsDataEnciphermentEnabled() bool { return k.Bits&KeyUsageDataEncipherment != 0 }
func (k KeyUsage) IsKeyAgreementEnabled() bool     { return k.Bits&KeyUsageKeyAgreement != 0 }
func (k KeyUsage) IsKeyCertSignEnabled() bool      { return k.Bits&KeyUsageKeyCertSign != 0 }
func (k KeyUsage) IsCRLSignEnabled() bool          { return k.Bits&KeyUsageCRLSign != 0 }
func (k KeyUsage) IsEncipherOnlyEnabled() bool     { return k.Bits&KeyUsageEncipherOnly != 0 }
func (k KeyUsage) IsDecipherOnlyEnabled() bool     { return k.Bits&KeyUsageDecipherOnly != 0 }

// EKU is a single extended key usage entry.
type EKU struct {
	OID  string
	Name string
}

// EKUs mirrors CadesEKUs.
type EKUs struct {
	items []EKU
}

// Count returns the number of entries.
func (e EKUs) Count() int { return len(e.items) }

// Item returns the entry at index i.
func (e EKUs) Item(i int) (EKU, error) {
	if i < 0 || i >= len(e.items) {
		return EKU{}, fmt.Errorf("gocades: EKU index %d out of range [0,%d)", i, len(e.items))
	}
	return e.items[i], nil
}

// ExtendedKeyUsage mirrors CadesExtendedKeyUsage.
type ExtendedKeyUsage struct {
	Present  bool
	Critical bool
	EKUs     EKUs
}

// BasicConstraints mirrors CadesBasicConstraints.
type BasicConstraints struct {
	Present                    bool
	Critical                   bool
	IsCertificateAuthority     bool
	IsPathLenConstraintPresent bool
	PathLenConstraint          uint32
}

// PublicKey mirrors CadesPublicKey.
type PublicKey struct {
	algorithm         string
	encodedKey        []byte
	encodedParameters []byte
	length            int
}

// Algorithm returns the SubjectPublicKeyInfo algorithm OID, like
// CadesPublicKey.Algorithm (a CadesOID object in pycades).
func (p *PublicKey) Algorithm() *OID { return NewOID(p.algorithm) }

// AlgorithmOID returns the algorithm OID as a plain string.
func (p *PublicKey) AlgorithmOID() string { return p.algorithm }

// Length returns the key size in bits.
func (p *PublicKey) Length() int { return p.length }

// EncodedKey returns the raw public key bits.
func (p *PublicKey) EncodedKey() *EncodedData { return NewEncodedData(p.encodedKey) }

// EncodedParameters returns the algorithm parameters.
func (p *PublicKey) EncodedParameters() *EncodedData {
	return NewEncodedData(p.encodedParameters)
}

// PrivateKey mirrors CadesPrivateKey.
type PrivateKey struct {
	ContainerName       string
	UniqueContainerName string
	ProviderName        string
	ProviderType        uint32
	KeySpec             uint32

	cert *Certificate
}

// ChangePin changes the key container PIN, like CadesPrivateKey.ChangePin.
func (p *PrivateKey) ChangePin(oldPIN, newPIN string) error {
	if p.cert == nil {
		return ErrNilCertificate
	}
	return p.cert.changePIN(oldPIN, newPIN)
}

// IsDefaultPin reports whether the key container still has the default PIN
// or needs none, like CadesPrivateKey.IsDefaultPin (PP_PIN_INFO reports
// CRYPT_PIN_CLEAR). The container is opened silently; no PIN is asked for.
func (p *PrivateKey) IsDefaultPin() (bool, error) {
	if p.cert == nil {
		return false, ErrNilCertificate
	}
	h, err := p.cert.handle()
	if err != nil {
		return false, err
	}
	var out C.int32_t
	rc := C.cp_cert_is_default_pin(h, &out)
	runtime.KeepAlive(p.cert)
	if err := hrErr("PrivateKey.IsDefaultPin", rc); err != nil {
		return false, err
	}
	return out != 0, nil
}

// changePIN changes the container PIN via PP_CHANGE_PASSWORD.
func (c *Certificate) changePIN(oldPIN, newPIN string) error {
	h, err := c.handle()
	if err != nil {
		return err
	}
	cold := C.CString(oldPIN)
	defer freeSecret(cold, len(oldPIN))
	cnew := C.CString(newPIN)
	defer freeSecret(cnew, len(newPIN))

	// AT_SIGNATURE == 2: the signing key PIN.
	rc := C.cp_change_pin(h, 2, cold, cnew)
	runtime.KeepAlive(c)
	return hrErr("Certificate.ChangePIN", rc)
}

// CertificateStatus mirrors CadesCertificateStatus.
type CertificateStatus struct {
	// Result is true when the chain validated successfully.
	Result bool
	// PolicyError is the chain policy error code (0 on success), e.g.
	// CRYPT_E_REVOKED or CRYPT_E_REVOCATION_OFFLINE; see ErrorText.
	PolicyError uint32
	// ChainStatus is the CERT_TRUST_* error bit mask of the built chain
	// (ChainRevoked, ChainRevocationUnknown, ...).
	ChainStatus uint32
}

// CERT_TRUST_* bits reported in CertificateStatus.ChainStatus.
const (
	ChainNotTimeValid          uint32 = 0x00000001
	ChainRevoked               uint32 = 0x00000004
	ChainNotSignatureValid     uint32 = 0x00000008
	ChainNotValidForUsage      uint32 = 0x00000010
	ChainUntrustedRoot         uint32 = 0x00000020
	ChainRevocationUnknown     uint32 = 0x00000040
	ChainPartial               uint32 = 0x00010000
	ChainOfflineRevocation     uint32 = 0x01000000
	ChainNoIssuanceChainPolicy uint32 = 0x02000000
)

// Revocation selects how IsValidWith checks revocation. Every mode skips
// the root, like CAPICOM_CHECK_ONLINE_ALL / CAPICOM_CHECK_OFFLINE_ALL.
type Revocation int32

const (
	// RevocationOnline fetches CRLs/OCSP over the network when the cache
	// has nothing current. An unknown status makes the certificate invalid.
	// This is the IsValid default, as in CAdESCOM.
	RevocationOnline Revocation = C.CP_REVOCATION_ONLINE
	// RevocationCacheOnly uses only CRLs already in the stores and cache.
	RevocationCacheOnly Revocation = C.CP_REVOCATION_CACHE_ONLY
	// RevocationNone skips revocation checking.
	RevocationNone Revocation = C.CP_REVOCATION_NONE
)

// ValidateOptions tunes IsValidWith; the zero value is what IsValid uses.
type ValidateOptions struct {
	Revocation Revocation
	// Time is the moment the chain is validated for; zero means now
	// (CadesCertificateStatus.VerificationTime).
	Time time.Time
	// URLTimeout bounds the total time spent fetching CRLs, OCSP responses
	// and issuer certificates; zero keeps the CryptoAPI default
	// (CadesCertificateStatus.UrlRetrievalTimeout).
	URLTimeout time.Duration
}

// ValidFrom returns the start of the validity period.
func (c *Certificate) ValidFrom() (time.Time, error) {
	h, err := c.handle()
	if err != nil {
		return time.Time{}, err
	}
	var secs C.int64_t
	rc := C.cp_cert_valid_from(h, &secs)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.ValidFrom", rc); err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(secs), 0).UTC(), nil
}

// ValidTo returns the end of the validity period.
func (c *Certificate) ValidTo() (time.Time, error) {
	h, err := c.handle()
	if err != nil {
		return time.Time{}, err
	}
	var secs C.int64_t
	rc := C.cp_cert_valid_to(h, &secs)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.ValidTo", rc); err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(secs), 0).UTC(), nil
}

// Version returns the X.509 version (1, 2 or 3), like CadesCertificate.Version.
func (c *Certificate) Version() (int, error) {
	h, err := c.handle()
	if err != nil {
		return 0, err
	}
	var v C.int32_t
	rc := C.cp_cert_version(h, &v)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.Version", rc); err != nil {
		return 0, err
	}
	return int(v), nil
}

// Info returns a certificate name field, like CadesCertificate.GetInfo.
//
// An absent field (no e-mail, no UPN, ...) yields an empty string.
func (c *Certificate) Info(t CertInfoType) (string, error) {
	return c.certString("Certificate.Info", func(h unsafe.Pointer, b *C.cp_buf) C.int32_t {
		return C.cp_cert_info(h, C.int32_t(t), b)
	})
}

// KeyUsage returns the KeyUsage extension.
func (c *Certificate) KeyUsage() (KeyUsage, error) {
	h, err := c.handle()
	if err != nil {
		return KeyUsage{}, err
	}
	var ku C.cp_key_usage
	rc := C.cp_cert_key_usage(h, &ku)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.KeyUsage", rc); err != nil {
		return KeyUsage{}, err
	}
	return KeyUsage{
		Present:  ku.present != 0,
		Critical: ku.critical != 0,
		Bits:     KeyUsageBits(ku.bits),
	}, nil
}

// ExtendedKeyUsage returns the ExtendedKeyUsage extension.
func (c *Certificate) ExtendedKeyUsage() (ExtendedKeyUsage, error) {
	h, err := c.handle()
	if err != nil {
		return ExtendedKeyUsage{}, err
	}
	var (
		list     C.cp_str_list
		critical C.int32_t
		present  C.int32_t
	)
	rc := C.cp_cert_eku(h, &list, &critical, &present)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.ExtendedKeyUsage", rc); err != nil {
		return ExtendedKeyUsage{}, err
	}

	oids := strListToGo(list)
	ekus := make([]EKU, 0, len(oids))
	for _, oid := range oids {
		ekus = append(ekus, EKU{OID: oid, Name: oidName(oid)})
	}

	return ExtendedKeyUsage{
		Present:  present != 0,
		Critical: critical != 0,
		EKUs:     EKUs{items: ekus},
	}, nil
}

// BasicConstraints returns the BasicConstraints extension.
func (c *Certificate) BasicConstraints() (BasicConstraints, error) {
	h, err := c.handle()
	if err != nil {
		return BasicConstraints{}, err
	}
	var bc C.cp_basic_constraints
	rc := C.cp_cert_basic_constraints(h, &bc)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.BasicConstraints", rc); err != nil {
		return BasicConstraints{}, err
	}
	return BasicConstraints{
		Present:                    bc.present != 0,
		Critical:                   bc.critical != 0,
		IsCertificateAuthority:     bc.is_ca != 0,
		IsPathLenConstraintPresent: bc.path_len_present != 0,
		PathLenConstraint:          uint32(bc.path_len),
	}, nil
}

// PublicKey returns the subject public key.
func (c *Certificate) PublicKey() (*PublicKey, error) {
	h, err := c.handle()
	if err != nil {
		return nil, err
	}
	var (
		key    C.cp_buf
		params C.cp_buf
		oid    *C.char
		bits   C.int32_t
	)
	rc := C.cp_cert_public_key(h, &key, &params, &oid, &bits)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.PublicKey", rc); err != nil {
		return nil, err
	}
	defer C.cp_free(unsafe.Pointer(oid))

	return &PublicKey{
		algorithm:         C.GoString(oid),
		encodedKey:        bufToBytes(key),
		encodedParameters: bufToBytes(params),
		length:            int(bits),
	}, nil
}

// PrivateKey returns the key container description, like
// CadesCertificate.PrivateKey. It reports ErrNoPrivateKey when the certificate
// has no associated container.
func (c *Certificate) PrivateKey() (*PrivateKey, error) {
	h, err := c.handle()
	if err != nil {
		return nil, err
	}
	var kpi C.cp_key_prov_info
	rc := C.cp_cert_key_prov_info(h, &kpi)
	runtime.KeepAlive(c)
	if err := hrErr("Certificate.PrivateKey", rc); err != nil {
		return nil, err
	}
	if kpi.present == 0 {
		return nil, ErrNoPrivateKey
	}
	defer C.cp_free(unsafe.Pointer(kpi.container))
	defer C.cp_free(unsafe.Pointer(kpi.unique_container))
	defer C.cp_free(unsafe.Pointer(kpi.provider))

	return &PrivateKey{
		ContainerName:       C.GoString(kpi.container),
		UniqueContainerName: C.GoString(kpi.unique_container),
		ProviderName:        C.GoString(kpi.provider),
		ProviderType:        uint32(kpi.provider_type),
		KeySpec:             uint32(kpi.key_spec),
		cert:                c,
	}, nil
}

// AdditionalStore registers an extra store used to build the chain in IsValid,
// like CadesCertificate.AdditionalStore.
func (c *Certificate) AdditionalStore(s *Store) {
	c.additional = s
}

// IsValid builds the certificate chain, checks revocation online for every
// certificate except the root and applies the base chain policy, like
// CadesCertificate.IsValid (CAPICOM_CHECK_ONLINE_ALL). Without network
// access to the CRL distribution points the result is false with
// PolicyError CRYPT_E_REVOCATION_OFFLINE; use IsValidWith to relax that.
func (c *Certificate) IsValid() (CertificateStatus, error) {
	return c.IsValidWith(ValidateOptions{})
}

// IsValidWith is IsValid with an explicit revocation mode, validation time
// and URL retrieval timeout.
func (c *Certificate) IsValidWith(opts ValidateOptions) (CertificateStatus, error) {
	h, err := c.handle()
	if err != nil {
		return CertificateStatus{}, err
	}
	hStore, err := optionalStoreHandle(c.additional)
	if err != nil {
		return CertificateStatus{}, err
	}
	var at int64
	if !opts.Time.IsZero() {
		at = opts.Time.Unix()
	}
	if opts.URLTimeout < 0 || opts.URLTimeout.Milliseconds() > math.MaxUint32 {
		return CertificateStatus{}, &Error{Op: "Certificate.IsValid", Code: hrEInvalidArg}
	}

	var (
		valid       C.int32_t
		policyError C.uint32_t
		chainStatus C.uint32_t
	)
	rc := C.cp_cert_is_valid(h, hStore, C.int32_t(opts.Revocation), C.int64_t(at),
		C.uint32_t(opts.URLTimeout.Milliseconds()), &valid, &policyError, &chainStatus)
	runtime.KeepAlive(c)
	runtime.KeepAlive(c.additional)
	if err := hrErr("Certificate.IsValid", rc); err != nil {
		return CertificateStatus{}, err
	}
	return CertificateStatus{
		Result:      valid != 0,
		PolicyError: uint32(policyError),
		ChainStatus: uint32(chainStatus),
	}, nil
}

// FindPrivateKey checks that the key container referenced by the certificate is
// usable, like CadesCertificate.FindPrivateKey.
//
// The C API has no search-criteria support: the container is taken from the
// certificate itself, so this only validates that it exists and can be opened
// far enough to be described.
func (c *Certificate) FindPrivateKey() error {
	if _, err := c.PrivateKey(); err != nil {
		return err
	}
	return nil
}

// strListToGo copies a C string list into Go strings and frees it.
func strListToGo(l C.cp_str_list) []string {
	defer C.cp_str_list_free(l)
	if l.len == 0 {
		return nil
	}

	items := unsafe.Slice(l.items, int(l.len))
	out := make([]string, 0, len(items))
	for _, p := range items {
		out = append(out, C.GoString(p))
	}
	return out
}
