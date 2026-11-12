//go:build (linux || darwin) && cgo

package gocades

import (
	"fmt"
	"time"
)

// SignatureStatus mirrors CadesSignatureStatus.
type SignatureStatus struct {
	// IsValid reports whether the signature verified successfully.
	IsValid bool
	// Status is the ADES_VERIFY_* status of this signer, VerifyFailed when
	// the verification failed without one.
	Status int32
	// Err is the verification error of this signer (a *VerifyError); nil
	// when IsValid.
	Err error
}

// Signer mirrors CadesSigner.
type Signer struct {
	// Certificate is the signer certificate taken from the CMS.
	Certificate *Certificate
	// SigningTime is the CMS signingTime attribute.
	SigningTime time.Time
	// SignatureTimeStampTime is the TSA time of the signature timestamp.
	SignatureTimeStampTime time.Time
	// SignatureStatus is the verification result for this signer.
	SignatureStatus SignatureStatus
	// TSAAddress is the timestamp authority used for signing.
	TSAAddress string
	// CheckCertificate mirrors CadesSigner.CheckCertificate.
	CheckCertificate bool
	// AuthenticatedAttributes are the CMS signed attributes, like
	// CadesSigner.AuthenticatedAttributes.
	AuthenticatedAttributes Attributes
	// UnauthenticatedAttributes are the CMS unsigned attributes, like
	// CadesSigner.UnauthenticatedAttributes.
	UnauthenticatedAttributes Attributes
	// CRLs are the DER CRLs of the revocation-values attribute (CAdES-X Long
	// Type 1 and later), like CadesSigner.CRLs; empty for other signatures.
	CRLs Blobs
	// OCSPResponses are the DER BasicOCSPResponses of the revocation-values
	// attribute, like CadesSigner.OCSPResponses.
	OCSPResponses Blobs
}

// Signers mirrors CadesSigners.
type Signers struct {
	items []Signer
}

// Count returns the number of signers.
func (s Signers) Count() int { return len(s.items) }

// Item returns the signer at index i.
func (s Signers) Item(i int) (Signer, error) {
	if i < 0 || i >= len(s.items) {
		return Signer{}, fmt.Errorf("gocades: signer index %d out of range [0,%d)", i, len(s.items))
	}
	return s.items[i], nil
}

// All returns all signers.
func (s Signers) All() []Signer { return s.items }

// Close releases the certificates held by the signers.
func (s Signers) Close() {
	for _, sg := range s.items {
		if sg.Certificate != nil {
			sg.Certificate.Close()
		}
	}
}
