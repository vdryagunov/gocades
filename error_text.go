//go:generate sh -c "./scripts/gen-error-names.sh > error_names.go"

package gocades

import "fmt"

// errorTexts holds short descriptions for the HRESULTs a caller is most likely
// to meet. Symbolic names in errorNames cover the rest; a code unknown to both
// is reported as plain hex.
//
// CryptoPro has no public API for this: CadesFormatMessage only formats
// CAdES-internal message ids, and the texts used by the vendor tools live in an
// undocumented catalog (<cprocsp>/share/locale/*/LC_MESSAGES/csp_error_messages.cat).
// pycades relies on Win32 FormatMessage, which the Unix CryptoAPI emulation does
// not provide, so the table below is maintained by hand.
var errorTexts = map[uint32]string{
	0x80070005: "access denied",
	0x8007000E: "out of memory",
	0x80070057: "invalid argument",

	0x80090001: "bad key container handle",
	0x80090002: "bad hash object",
	0x80090003: "bad key",
	0x80090004: "bad length",
	0x80090005: "bad data",
	0x80090006: "bad signature",
	0x80090007: "unsupported provider version",
	0x80090008: "invalid algorithm",
	0x80090009: "invalid flags",
	0x8009000A: "invalid type",
	0x8009000B: "key is not usable in its current state " +
		"(wrong PIN, missing key or key-usage mismatch)",
	0x8009000C: "hash object is not usable in its current state",
	0x8009000D: "key does not exist (wrong key type or empty container)",
	0x8009000E: "out of memory",
	0x8009000F: "object already exists",
	0x80090010: "access denied by the provider (insufficient rights or wrong PIN)",
	0x80090011: "object not found",
	0x80090012: "data is already encrypted",
	0x80090013: "invalid provider",
	0x80090014: "invalid provider type",
	0x80090015: "invalid public key",
	0x80090016: "key container does not exist",
	0x80090019: "key container is not defined",
	0x8009001A: "key container registration is invalid",
	0x8009001D: "CSP provider library could not be loaded",
	0x80090020: "internal CSP error",

	0x80092004: "object or property not found",
	0x8009200B: "certificate has no private key property",
	0x8009200C: "no certificate for decryption",
	0x8009200D: "bad PKCS message",
	0x80092012: "revocation function could not check revocation",
	0x80092013: "revocation server is offline (CRL or OCSP responder unreachable)",

	0x800B0100: "subject has no signature",
	0x800B0101: "certificate has expired",
	0x800B0109: "certificate chain ends in an untrusted root",
	0x800B010A: "cannot build a certificate chain to a trusted root",
	0x800B010E: "revocation status of a chain certificate could not be checked " +
		"(CRL/OCSP unreachable or the root is not trusted)",

	0x8010002C: "no such certificate on the smart card",

	// CryptoPro TSP/OCSP clients and CAdES (tspcli_e.h, ocspcli_e.h, cades_e.h).
	0xC2100100: "TSA request failed at the HTTP level (address, network or proxy)",
	0xC2100124: "TSA returned an unsuccessful response",
	0xC2100140: "CryptoPro TSP Client licence is missing or expired",
	0xC2110100: "OCSP request failed at the HTTP level (address, network or proxy)",
	0xC2110140: "CryptoPro OCSP Client licence is missing or expired",
	0xC2140104: "revocation status of the TSA certificate could not be checked",

	// CryptoPro-specific: temporary or expired CSP licence.
	0x200000DF: "CryptoPro CSP licence is missing, expired or invalid",
}

// ErrorText returns a description for a CryptoPro/CryptoAPI HRESULT code.
// The result is either "<SYMBOLIC_NAME>: <description>", just the symbolic
// name, or "" when the code is unknown.
//
// The code is a uint32 because HRESULTs do not fit into int32 as literals:
// ErrorText(0x8009000B) reads naturally, whereas int32 would overflow.
func ErrorText(code uint32) string {
	text, hasText := errorTexts[code]
	name, hasName := errorNames[code]

	switch {
	case hasText && hasName:
		return fmt.Sprintf("%s: %s", name, text)
	case hasText:
		return text
	default:
		return name
	}
}
