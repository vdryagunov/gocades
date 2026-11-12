//go:build (linux || darwin) && cgo

package gocades

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CertFindType mirrors CAPICOM_CERTIFICATE_FIND_TYPE.
type CertFindType int32

const (
	FindBySHA1Hash          CertFindType = 0
	FindBySubjectName       CertFindType = 1
	FindByIssuerName        CertFindType = 2
	FindByRootName          CertFindType = 3
	FindByTemplateName      CertFindType = 4
	FindByExtension         CertFindType = 5
	FindByExtendedProperty  CertFindType = 6
	FindByApplicationPolicy CertFindType = 7
	FindByCertificatePolicy CertFindType = 8
	FindByTimeValid         CertFindType = 9
	FindByTimeNotYetValid   CertFindType = 10
	FindByTimeExpired       CertFindType = 11
	FindByKeyUsage          CertFindType = 12
)

func (t CertFindType) String() string {
	switch t {
	case FindBySHA1Hash:
		return "SHA1_HASH"
	case FindBySubjectName:
		return "SUBJECT_NAME"
	case FindByIssuerName:
		return "ISSUER_NAME"
	case FindByRootName:
		return "ROOT_NAME"
	case FindByTemplateName:
		return "TEMPLATE_NAME"
	case FindByExtension:
		return "EXTENSION"
	case FindByExtendedProperty:
		return "EXTENDED_PROPERTY"
	case FindByApplicationPolicy:
		return "APPLICATION_POLICY"
	case FindByCertificatePolicy:
		return "CERTIFICATE_POLICY"
	case FindByTimeValid:
		return "TIME_VALID"
	case FindByTimeNotYetValid:
		return "TIME_NOT_YET_VALID"
	case FindByTimeExpired:
		return "TIME_EXPIRED"
	case FindByKeyUsage:
		return "KEY_USAGE"
	}
	return "UNKNOWN"
}

// Find returns the certificates that match a CAPICOM criterion, like
// CadesCertificates.Find.
//
// value is interpreted per findType:
//
//	FindBySHA1Hash        SHA-1 thumbprint as hex, ":" and spaces are ignored
//	FindBySubjectName     case-insensitive substring of the subject
//	FindByIssuerName      case-insensitive substring of the issuer
//	FindByKeyUsage        bitmask or comma separated names, e.g.
//	                      "digitalSignature,nonRepudiation"
//	FindByTime*           value is ignored
//
// validOnly additionally drops the certificates outside their validity period.
//
// The comparison runs over the store enumeration: the CryptoPro C API
// emulation does not provide CERT_FIND_TEMPLATE or CERT_FIND_EXTENSION, so
// FindByTemplateName, FindByExtension, FindByRootName, FindByApplicationPolicy
// and FindByCertificatePolicy are not supported.
//
// The caller owns the returned certificates and must call Close on each of
// them.
func (s *Store) Find(findType CertFindType, value string, validOnly bool) ([]*Certificate, error) {
	switch findType {
	case FindBySHA1Hash, FindBySubjectName, FindByIssuerName,
		FindByTimeValid, FindByTimeNotYetValid, FindByTimeExpired, FindByKeyUsage:
	default:
		return nil, fmt.Errorf("gocades: find type %s is not supported by the CryptoPro C API", findType)
	}

	// Validate the filter before enumerating so a bad value closes nothing.
	if findType == FindByKeyUsage {
		if _, err := parseKeyUsageBits(value); err != nil {
			return nil, err
		}
	}

	certs, err := s.Certificates()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	out := make([]*Certificate, 0, len(certs))

	for _, c := range certs {
		keep, err := certificateMatches(c, findType, value, now)
		if err != nil {
			c.Close()
			for _, rest := range out {
				rest.Close()
			}
			return nil, err
		}

		if !keep || (validOnly && !validAt(c, now)) {
			c.Close()
			continue
		}
		out = append(out, c)
	}

	return out, nil
}

// First returns the first match of a criterion, or nil when nothing matched.
func (s *Store) First(findType CertFindType, value string, validOnly bool) (*Certificate, error) {
	found, err := s.Find(findType, value, validOnly)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}
	for _, extra := range found[1:] {
		extra.Close()
	}
	return found[0], nil
}

func certificateMatches(c *Certificate, findType CertFindType, value string, now time.Time) (bool, error) {
	switch findType {
	case FindBySHA1Hash:
		tp, err := c.Thumbprint()
		if err != nil {
			return false, err
		}
		return strings.EqualFold(normalizeHex(tp), normalizeHex(value)), nil

	case FindBySubjectName:
		subject, err := c.SubjectName()
		if err != nil {
			return false, err
		}
		return containsFold(subject, value), nil

	case FindByIssuerName:
		issuer, err := c.IssuerName()
		if err != nil {
			return false, err
		}
		return containsFold(issuer, value), nil

	case FindByTimeValid:
		return validAt(c, now), nil

	case FindByTimeNotYetValid:
		from, err := c.ValidFrom()
		if err != nil {
			return false, err
		}
		return now.Before(from), nil

	case FindByTimeExpired:
		to, err := c.ValidTo()
		if err != nil {
			return false, err
		}
		return now.After(to), nil

	case FindByKeyUsage:
		want, err := parseKeyUsageBits(value)
		if err != nil {
			return false, err
		}
		ku, err := c.KeyUsage()
		if err != nil {
			return false, err
		}
		return ku.Present && ku.Bits&want == want, nil
	}

	return false, nil
}

func validAt(c *Certificate, now time.Time) bool {
	from, err := c.ValidFrom()
	if err != nil {
		return false
	}
	to, err := c.ValidTo()
	if err != nil {
		return false
	}
	return !now.Before(from) && !now.After(to)
}

// normalizeHex drops separators and lowercases a hex string.
func normalizeHex(s string) string {
	s = strings.NewReplacer(":", "", " ", "", "-", "").Replace(s)
	return strings.ToLower(s)
}

func containsFold(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// parseKeyUsageBits accepts a numeric bitmask or a comma separated list of
// KeyUsage names.
func parseKeyUsageBits(value string) (KeyUsageBits, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("gocades: empty key usage filter")
	}

	if n, err := strconv.ParseUint(value, 0, 32); err == nil {
		return KeyUsageBits(n), nil
	}

	var bits KeyUsageBits
	for _, part := range strings.Split(value, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "digitalsignature":
			bits |= KeyUsageDigitalSignature
		case "nonrepudiation", "contentcommitment":
			bits |= KeyUsageNonRepudiation
		case "keyencipherment":
			bits |= KeyUsageKeyEncipherment
		case "dataencipherment":
			bits |= KeyUsageDataEncipherment
		case "keyagreement":
			bits |= KeyUsageKeyAgreement
		case "keycertsign":
			bits |= KeyUsageKeyCertSign
		case "crlsign":
			bits |= KeyUsageCRLSign
		case "encipheronly":
			bits |= KeyUsageEncipherOnly
		case "decipheronly":
			bits |= KeyUsageDecipherOnly
		default:
			return 0, fmt.Errorf("gocades: unknown key usage %q", strings.TrimSpace(part))
		}
	}
	return bits, nil
}
