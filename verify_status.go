package gocades

// ADES verification status codes returned by CadesVerifyMessage /
// CadesVerifyDetachedMessage in CADES_VERIFICATION_INFO.dwStatus.
//
// They mirror the ADES_VERIFY_* constants from ades-core.h. Zero means success.
const (
	VerifySuccess                   int32 = 0x00
	VerifyInvalidRefsAndValues      int32 = 0x01
	VerifySignerNotFound            int32 = 0x02
	VerifyNoValidSignatureTimestamp int32 = 0x03
	VerifyRefsAndValuesNoMatch      int32 = 0x04
	VerifyNoChain                   int32 = 0x05
	VerifyEndCertRevocation         int32 = 0x06
	VerifyChainCertRevocation       int32 = 0x07
	VerifyBadSignature              int32 = 0x08
	VerifyNoValidCadesCTimestamp    int32 = 0x09
	VerifyBadPolicy                 int32 = 0x0A
	VerifyUnsupportedAttribute      int32 = 0x0B
	VerifyFailedPolicy              int32 = 0x0C
	VerifyEContentTypeNoMatch       int32 = 0x0D
	VerifyNoValidArchiveTimestamp   int32 = 0x0E

	// VerifyFailed is not an ADES_VERIFY_* code: the verification failed
	// before CAdES produced a status (malformed CMS, missing content, …) or
	// failed while CAdES reported success. VerifyError.Code has the reason.
	VerifyFailed int32 = -1
)

var verifyStatusText = map[int32]string{
	VerifySuccess:                   "signature is valid",
	VerifyInvalidRefsAndValues:      "invalid signed references or signed values",
	VerifySignerNotFound:            "signer certificate not found",
	VerifyNoValidSignatureTimestamp: "no valid signature timestamp",
	VerifyRefsAndValuesNoMatch:      "signed references do not match the content",
	VerifyNoChain:                   "certificate chain could not be built",
	VerifyEndCertRevocation:         "end certificate is revoked or its status is unknown",
	VerifyChainCertRevocation:       "chain certificate is revoked or its status is unknown",
	VerifyBadSignature:              "signature value is invalid",
	VerifyNoValidCadesCTimestamp:    "no valid CAdES-C timestamp",
	VerifyBadPolicy:                 "signature policy does not match",
	VerifyUnsupportedAttribute:      "unsupported signed attribute",
	VerifyFailedPolicy:              "signature policy check failed",
	VerifyEContentTypeNoMatch:       "eContentType does not match the signature",
	VerifyNoValidArchiveTimestamp:   "no valid archive timestamp",
	VerifyFailed:                    "verification failed",
}

// VerifyStatusText returns a human-readable description of an ADES_VERIFY_*
// status code.
func VerifyStatusText(code int32) string {
	if s, ok := verifyStatusText[code]; ok {
		return s
	}
	return "verification failed with an unknown status"
}
