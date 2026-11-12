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

// VerificationInfo describes the outcome of signature verification.
type VerificationInfo struct {
	// Status is the ADES_VERIFY_* status code; VerifySuccess (0) is valid.
	// VerifyFailed means the verification failed without a CAdES status.
	Status int32
	// Valid reports whether Status is VerifySuccess.
	Valid bool
	// SignerCertificate is the signer certificate taken from the CMS.
	SignerCertificate *Certificate
	// SigningTime is the CMS signingTime attribute; zero when absent.
	SigningTime time.Time
	// SignatureTimeStampTime is the TSA time of the signature timestamp.
	SignatureTimeStampTime time.Time
	// CadesCTimeStampTime is the earliest CAdES-C timestamp time.
	CadesCTimeStampTime time.Time
	// ArchiveTimeStampTime is the latest archive timestamp time.
	ArchiveTimeStampTime time.Time
}

// Close releases the signer certificate.
func (v *VerificationInfo) Close() {
	if v.SignerCertificate != nil {
		v.SignerCertificate.Close()
		v.SignerCertificate = nil
	}
}

func unixOrZero(secs int64) time.Time {
	if secs <= 0 {
		return time.Time{}
	}
	return time.Unix(secs, 0).UTC()
}

func verificationInfoFromC(ci C.cp_verify_info) VerificationInfo {
	info := VerificationInfo{
		Status:                 int32(ci.status),
		Valid:                  int32(ci.status) == VerifySuccess,
		SigningTime:            unixOrZero(int64(ci.signing_time)),
		SignatureTimeStampTime: unixOrZero(int64(ci.signature_ts_time)),
		CadesCTimeStampTime:    unixOrZero(int64(ci.cades_c_ts_time)),
		ArchiveTimeStampTime:   unixOrZero(int64(ci.archive_ts_time)),
	}
	if ci.signer_cert != nil {
		info.SignerCertificate = newCertificate(unsafe.Pointer(ci.signer_cert))
	}
	return info
}

// verifyOutcome converts the result of a verification call. The info is kept
// on failure too: CAdES reports the status and the signer certificate of an
// invalid signature. On failure Status never reads as VerifySuccess.
func verifyOutcome(op string, index int, rc C.int32_t, ci C.cp_verify_info) (VerificationInfo, error) {
	info := verificationInfoFromC(ci)
	err := verifyErr(op, index, int32(rc), info.Status)
	if ve, ok := err.(*VerifyError); ok {
		info.Status = ve.Status
	}
	info.Valid = err == nil
	return info, err
}

// verifyMessageInfo verifies signature number index of a (detached or attached)
// CMS and returns the signer information, also when the signature is invalid.
// The error is a *VerifyError for a failed verification.
func verifyMessageInfo(op string, sig, content []byte, typ CadesType, detached bool, store *Store, index int) (VerificationInfo, error) {
	hStore, err := optionalStoreHandle(store)
	if err != nil {
		return VerificationInfo{}, err
	}

	var ci C.cp_verify_info
	rc := C.cp_verify_message(
		bytesPtr(sig), C.size_t(len(sig)),
		C.int32_t(typ), boolToC(detached),
		bytesPtr(content), C.size_t(len(content)),
		C.int32_t(index), hStore, &ci)
	runtime.KeepAlive(store)

	return verifyOutcome(op, index, rc, ci)
}

// verifyHashInfo verifies signature number index against a precomputed digest,
// with the same contract as verifyMessageInfo.
func verifyHashInfo(op string, sig, digest []byte, typ CadesType, hashOID string, store *Store, index int) (VerificationInfo, error) {
	hStore, err := optionalStoreHandle(store)
	if err != nil {
		return VerificationInfo{}, err
	}

	coid := C.CString(hashOID)
	defer C.free(unsafe.Pointer(coid))

	var ci C.cp_verify_info
	rc := C.cp_verify_hash(
		bytesPtr(sig), C.size_t(len(sig)),
		C.int32_t(typ), coid,
		bytesPtr(digest), C.size_t(len(digest)),
		C.int32_t(index), hStore, &ci)
	runtime.KeepAlive(store)

	return verifyOutcome(op, index, rc, ci)
}
