package gocades

import (
	"errors"
	"fmt"
)

// ErrNilCertificate is returned when a nil certificate handle is passed.
var ErrNilCertificate = errors.New("gocades: nil certificate")

// ErrClosed is returned when a closed (or never opened) object is used.
var ErrClosed = errors.New("gocades: object is closed")

// ErrNotInitialized is returned by the getters of an object that was created
// empty and never imported, such as NewCRL.
var ErrNotInitialized = errors.New("gocades: object is not initialized")

// ErrNoPrivateKey is returned when a certificate has no associated key
// container.
var ErrNoPrivateKey = errors.New("gocades: certificate has no private key")

// ErrUnsupported is returned by ported methods that have no implementation yet.
var ErrUnsupported = errors.New("gocades: operation is not supported by this port")

// ErrBadSignature is returned when raw signature verification fails.
var ErrBadSignature = errors.New("gocades: bad signature")

// Well known HRESULT codes, as int32 (the sign-extended form).
const (
	// hrEInvalidArg is E_INVALIDARG (0x80070057).
	hrEInvalidArg int32 = -2147024809
	// hrCryptENotFound is CRYPT_E_NOT_FOUND (0x80092004).
	hrCryptENotFound int32 = -2146885628
	// hrNTEBadSignature is NTE_BAD_SIGNATURE (0x80090006).
	hrNTEBadSignature int32 = -2146893818
	// hrCryptENoSigner is CRYPT_E_NO_SIGNER (0x8009200E).
	hrCryptENoSigner int32 = -2146885618
)

// Error is a CryptoPro/CryptoAPI HRESULT-style error.
type Error struct {
	Op   string
	Code int32
}

func (e *Error) Error() string {
	if text := ErrorText(uint32(e.Code)); text != "" {
		return fmt.Sprintf("gocades: %s failed: 0x%08X (%s)", e.Op, uint32(e.Code), text)
	}
	return fmt.Sprintf("gocades: %s failed: 0x%08X", e.Op, uint32(e.Code))
}

// VerifyError reports a signature that did not verify. Like pycades, which
// raises on any result other than success, the verification calls return it
// for every failure, together with the verification info they could collect.
//
// errors.As(err, &*Error) also matches when Code is set.
type VerifyError struct {
	Op string
	// Signer is the index of the signer that failed.
	Signer int
	// Status is the ADES_VERIFY_* status, or VerifyFailed when CAdES produced
	// no verification info. It is never VerifySuccess.
	Status int32
	// Code is the HRESULT of the verification call; 0 when only Status
	// reports the failure.
	Code int32
}

func (e *VerifyError) Error() string {
	msg := fmt.Sprintf("gocades: %s: signer %d: %s", e.Op, e.Signer, VerifyStatusText(e.Status))
	if e.Code == 0 {
		return msg
	}
	if text := ErrorText(uint32(e.Code)); text != "" {
		return fmt.Sprintf("%s: 0x%08X (%s)", msg, uint32(e.Code), text)
	}
	return fmt.Sprintf("%s: 0x%08X", msg, uint32(e.Code))
}

// Unwrap exposes the HRESULT as an *Error.
func (e *VerifyError) Unwrap() error {
	if e.Code == 0 {
		return nil
	}
	return &Error{Op: e.Op, Code: e.Code}
}

// verifyErr builds the error for a verification outcome, or returns nil when
// both the call and the status report success.
func verifyErr(op string, signer int, code, status int32) error {
	if code == 0 && status == VerifySuccess {
		return nil
	}
	if status == VerifySuccess {
		status = VerifyFailed
	}
	return &VerifyError{Op: op, Signer: signer, Status: status, Code: code}
}
