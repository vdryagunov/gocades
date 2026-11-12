package gocades

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Attribute is one CMS attribute: an object identifier and its values.
type Attribute struct {
	// OID is the dotted attribute type, e.g. "1.2.840.113549.1.9.3".
	OID string
	// Name is the human readable name, or "" when unknown.
	Name string
	// AttrName is the CADESCOM_ATTRIBUTE enum used when building a signature.
	// Zero with an empty OID means unset; prefer SetName.
	AttrName AttributeName
	// ValueEncoding selects how SetValue interprets a string
	// (CadesAttribute.ValueEncoding). The default is EncodingBase64.
	ValueEncoding EncodingType
	// Values holds the raw content octets of every attribute value.
	Values [][]byte
}

// Value returns the first attribute value, or nil.
func (a Attribute) Value() []byte {
	if len(a.Values) == 0 {
		return nil
	}
	return a.Values[0]
}

// Attributes is an ordered collection of CMS attributes.
type Attributes struct {
	items []Attribute
}

// Count returns the number of attributes.
func (a Attributes) Count() int { return len(a.items) }

// Item returns the attribute at index i.
func (a Attributes) Item(i int) (Attribute, error) {
	if i < 0 || i >= len(a.items) {
		return Attribute{}, fmt.Errorf("gocades: attribute index %d out of range [0,%d)", i, len(a.items))
	}
	return a.items[i], nil
}

// All returns every attribute.
func (a Attributes) All() []Attribute { return a.items }

// Find returns the attribute with the given OID.
func (a Attributes) Find(oid string) (Attribute, bool) {
	for _, it := range a.items {
		if it.OID == oid {
			return it, true
		}
	}
	return Attribute{}, false
}

// AttributeName mirrors CADESCOM_ATTRIBUTE: named signed attributes.
type AttributeName int32

const (
	// AttrSigningTime is pkcs-9 signingTime (1.2.840.113549.1.9.5).
	AttrSigningTime AttributeName = 0
	// AttrDocumentName is CAPICOM documentName (1.3.6.1.4.1.311.88.2.1).
	AttrDocumentName AttributeName = 1
	// AttrDocumentDescription is CAPICOM documentDescription
	// (1.3.6.1.4.1.311.88.2.2).
	AttrDocumentDescription AttributeName = 2
	// AttrMachineInfo is CryptoPro machine info (1.2.643.2.74.2.1.1.1).
	AttrMachineInfo AttributeName = 0x100
	// AttrOther means the OID field alone selects the attribute type.
	AttrOther AttributeName = -1
)

func oidForAttributeName(n AttributeName) string {
	switch n {
	case AttrSigningTime:
		return "1.2.840.113549.1.9.5"
	case AttrDocumentName:
		return "1.3.6.1.4.1.311.88.2.1"
	case AttrDocumentDescription:
		return "1.3.6.1.4.1.311.88.2.2"
	case AttrMachineInfo:
		return "1.2.643.2.74.2.1.1.1"
	}
	return ""
}

// SetName selects a well-known attribute type and fills OID, like
// CadesAttribute.Name.
func (a *Attribute) SetName(n AttributeName) {
	a.AttrName = n
	if oid := oidForAttributeName(n); oid != "" {
		a.OID = oid
	}
}

// SetValueEncoding selects how SetValue interprets a string, like
// CadesAttribute.ValueEncoding.
func (a *Attribute) SetValueEncoding(t EncodingType) { a.ValueEncoding = t }

// SetValue sets the first attribute value from a string. With EncodingBase64
// the string is base64 of the content octets; with EncodingBinary it is the
// raw octets as a Go string. For AttrSigningTime the string is RFC3339 /
// "YYYYMMDDHHMMSSZ" and is encoded as ASN.1 UTCTime or GeneralizedTime.
func (a *Attribute) SetValue(s string) error {
	if a.OID == "" {
		if oid := oidForAttributeName(a.AttrName); oid != "" {
			a.OID = oid
		}
	}
	// AttrSigningTime is the zero AttrName; decide by the resolved OID only.
	if a.OID == oidForAttributeName(AttrSigningTime) {
		raw, err := encodeSigningTime(s)
		if err != nil {
			return err
		}
		a.Values = [][]byte{raw}
		return nil
	}
	var raw []byte
	switch a.ValueEncoding {
	case EncodingBinary:
		raw = []byte(s)
	default:
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			raw = []byte(s)
		} else {
			raw = decoded
		}
	}
	// CAPICOM documentName/Description store a CERT_NAME_VALUE (BMPString).
	if a.OID == oidForAttributeName(AttrDocumentName) ||
		a.OID == oidForAttributeName(AttrDocumentDescription) ||
		a.AttrName == AttrDocumentName || a.AttrName == AttrDocumentDescription {
		enc, err := encodeBMPString(string(raw))
		if err != nil {
			return err
		}
		raw = enc
	}
	a.Values = [][]byte{raw}
	return nil
}

// encodeBMPString encodes s as an ASN.1 BMPString (UTF-16BE), the form CAPICOM
// uses for documentName / documentDescription authenticated attributes.
func encodeBMPString(s string) ([]byte, error) {
	runes := []rune(s)
	body := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		if r > 0xFFFF {
			return nil, fmt.Errorf("gocades: BMPString cannot encode rune U+%X", r)
		}
		body = append(body, byte(r>>8), byte(r))
	}
	if len(body) > 127 {
		return nil, fmt.Errorf("gocades: BMPString too long")
	}
	return append([]byte{0x1e, byte(len(body))}, body...), nil
}

func encodeSigningTime(s string) ([]byte, error) {
	var t time.Time
	var err error
	for _, layout := range []string{time.RFC3339, "20060102150405Z", time.RFC3339Nano} {
		t, err = time.Parse(layout, s)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("gocades: signing time %q: %w", s, err)
	}
	if y := t.UTC().Year(); y >= 1950 && y < 2050 {
		body := t.UTC().Format("060102150405Z")
		return append([]byte{0x17, byte(len(body))}, body...), nil
	}
	body := t.UTC().Format("20060102150405Z")
	return append([]byte{0x18, byte(len(body))}, body...), nil
}

// Add appends attr, like CadesAttributes.Add.
func (a *Attributes) Add(attr Attribute) {
	if a == nil {
		return
	}
	if attr.OID == "" {
		if oid := oidForAttributeName(attr.AttrName); oid != "" {
			attr.OID = oid
		}
	}
	a.items = append(a.items, attr)
}

// Clear removes every attribute, like CadesAttributes.Clear.
func (a *Attributes) Clear() {
	if a != nil {
		a.items = nil
	}
}

// Remove deletes the attribute at index i, like CadesAttributes.Remove.
func (a *Attributes) Remove(i int) error {
	if a == nil || i < 0 || i >= len(a.items) {
		return fmt.Errorf("gocades: attribute index %d out of range", i)
	}
	a.items = append(a.items[:i], a.items[i+1:]...)
	return nil
}

// CMSSignerInfo holds the attributes of one CMS signer.
type CMSSignerInfo struct {
	SignedAttributes   Attributes
	UnsignedAttributes Attributes
}

/* ------------------------------------------------------------------ */
/* Minimal DER reader                                                  */
/* ------------------------------------------------------------------ */

type derElem struct {
	tag  byte
	data []byte
}

var errDER = fmt.Errorf("gocades: malformed DER")

// maxBERDepth bounds the nesting of indefinite-length elements, which are
// resolved recursively.
const maxBERDepth = 64

// derNext reads one TLV and returns it with the remaining bytes.
//
// Besides DER it accepts the BER indefinite length that CryptoAPI accepts
// too: a CMS re-encoded that way must not escape the signer enumeration.
func derNext(b []byte) (derElem, []byte, error) {
	return berNext(b, 0)
}

func berNext(b []byte, depth int) (derElem, []byte, error) {
	if len(b) < 2 {
		return derElem{}, nil, errDER
	}

	tag := b[0]
	if tag&0x1F == 0x1F {
		return derElem{}, nil, fmt.Errorf("%w: multi-byte tags are not supported", errDER)
	}

	length := int(b[1])
	pos := 2

	if length == 0x80 {
		// Indefinite length: constructed only, ends with 00 00.
		if tag&0x20 == 0 {
			return derElem{}, nil, fmt.Errorf("%w: indefinite length on a primitive", errDER)
		}
		if depth >= maxBERDepth {
			return derElem{}, nil, fmt.Errorf("%w: nesting too deep", errDER)
		}
		rest := b[pos:]
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				end := len(b) - len(rest)
				return derElem{tag: tag, data: b[pos:end]}, rest[2:], nil
			}
			var err error
			if _, rest, err = berNext(rest, depth+1); err != nil {
				return derElem{}, nil, err
			}
		}
	}

	if length&0x80 != 0 {
		n := length & 0x7F
		if n > 4 || len(b) < 2+n {
			return derElem{}, nil, errDER
		}
		length = 0
		for i := 0; i < n; i++ {
			length = length<<8 | int(b[2+i])
		}
		pos = 2 + n
	}

	if length < 0 || len(b)-pos < length {
		return derElem{}, nil, errDER
	}

	return derElem{tag: tag, data: b[pos : pos+length]}, b[pos+length:], nil
}

// derChildren splits a concatenation of TLVs into elements.
func derChildren(b []byte) ([]derElem, error) {
	var out []derElem
	for len(b) > 0 {
		e, rest, err := derNext(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = rest
	}
	return out, nil
}

// derOID decodes an OBJECT IDENTIFIER content.
//
// Arcs are arbitrary precision: 2.25 carries 128-bit UUIDs, and the first
// subidentifier spans several bytes once the second arc under 2 exceeds 47.
func derOID(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errDER
	}

	var sb strings.Builder
	v := new(big.Int)
	first := true
	start := true
	for _, c := range b {
		if start && c == 0x80 {
			return "", fmt.Errorf("%w: non-minimal OID subidentifier", errDER)
		}
		start = false
		v.Lsh(v, 7)
		v.Or(v, big.NewInt(int64(c&0x7F)))
		if c&0x80 != 0 {
			continue
		}

		if first {
			// The first subidentifier is 40*X + Y with X in 0..2.
			switch {
			case v.Cmp(big.NewInt(40)) < 0:
				fmt.Fprintf(&sb, "0.%s", v)
			case v.Cmp(big.NewInt(80)) < 0:
				fmt.Fprintf(&sb, "1.%s", v.Sub(v, big.NewInt(40)))
			default:
				fmt.Fprintf(&sb, "2.%s", v.Sub(v, big.NewInt(80)))
			}
			first = false
		} else {
			fmt.Fprintf(&sb, ".%s", v)
		}
		v.SetInt64(0)
		start = true
	}
	if !start {
		return "", fmt.Errorf("%w: truncated OID", errDER)
	}
	return sb.String(), nil
}

/* ------------------------------------------------------------------ */
/* CMS walking                                                         */
/* ------------------------------------------------------------------ */

// oidSignedData is the ContentInfo type of a CMS SignedData.
const oidSignedData = "1.2.840.113549.1.7.2"

// ParseCMSSignerInfos walks a CMS (PKCS#7) SignedData and returns the signed and
// unsigned attributes of every signer, in document order.
//
// The port has no accessor for attributes in cades.h, so they are read
// structurally from the DER encoding. Values are returned as raw content
// octets, not decoded types.
func ParseCMSSignerInfos(cms []byte) ([]CMSSignerInfo, error) {
	top, err := derChildren(cms)
	if err != nil {
		return nil, err
	}
	if len(top) == 0 || top[0].tag != 0x30 {
		return nil, fmt.Errorf("%w: expected a ContentInfo SEQUENCE", errDER)
	}

	contentInfo, err := derChildren(top[0].data)
	if err != nil {
		return nil, err
	}
	if len(contentInfo) < 2 {
		return nil, fmt.Errorf("%w: truncated ContentInfo", errDER)
	}

	if contentInfo[0].tag != 0x06 {
		return nil, fmt.Errorf("%w: missing contentType", errDER)
	}
	if oid, err := derOID(contentInfo[0].data); err != nil || oid != oidSignedData {
		return nil, fmt.Errorf("%w: not a SignedData content type", errDER)
	}

	// [0] EXPLICIT wrapping the SignedData SEQUENCE.
	if contentInfo[1].tag != 0xA0 {
		return nil, fmt.Errorf("%w: missing [0] content", errDER)
	}
	explicit, err := derChildren(contentInfo[1].data)
	if err != nil {
		return nil, err
	}
	if len(explicit) == 0 || explicit[0].tag != 0x30 {
		return nil, fmt.Errorf("%w: malformed SignedData", errDER)
	}

	parts, err := derChildren(explicit[0].data)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: empty SignedData", errDER)
	}

	// signerInfos is the trailing SET.
	signerInfos := parts[len(parts)-1]
	if signerInfos.tag != 0x31 {
		return nil, fmt.Errorf("%w: signerInfos is not a SET", errDER)
	}

	infos, err := derChildren(signerInfos.data)
	if err != nil {
		return nil, err
	}

	out := make([]CMSSignerInfo, 0, len(infos))
	for _, inf := range infos {
		// Skipping one would shift the indices against CAdES' signer numbers.
		if inf.tag != 0x30 {
			return nil, fmt.Errorf("%w: SignerInfo is not a SEQUENCE", errDER)
		}
		fields, err := derChildren(inf.data)
		if err != nil {
			return nil, err
		}

		var info CMSSignerInfo
		for _, f := range fields {
			switch f.tag {
			case 0xA0: // signedAttrs [0] IMPLICIT
				attrs, err := parseAttributes(f.data)
				if err != nil {
					return nil, err
				}
				info.SignedAttributes = attrs
			case 0xA1: // unsignedAttrs [1] IMPLICIT
				attrs, err := parseAttributes(f.data)
				if err != nil {
					return nil, err
				}
				info.UnsignedAttributes = attrs
			}
		}
		out = append(out, info)
	}

	return out, nil
}

// parseAttributes decodes a SET OF Attribute.
func parseAttributes(b []byte) (Attributes, error) {
	elems, err := derChildren(b)
	if err != nil {
		return Attributes{}, err
	}

	// A malformed attribute is an error, not skipped: a caller looking for
	// one must not get "absent" for "could not read".
	var out Attributes
	for _, e := range elems {
		if e.tag != 0x30 {
			return Attributes{}, fmt.Errorf("%w: attribute is not a SEQUENCE", errDER)
		}

		fields, err := derChildren(e.data)
		if err != nil {
			return Attributes{}, err
		}
		if len(fields) < 2 || fields[0].tag != 0x06 {
			return Attributes{}, fmt.Errorf("%w: attribute without a type", errDER)
		}

		oid, err := derOID(fields[0].data)
		if err != nil {
			return Attributes{}, err
		}

		var values [][]byte
		if fields[1].tag == 0x31 {
			vals, err := derChildren(fields[1].data)
			if err != nil {
				return Attributes{}, err
			}
			for _, v := range vals {
				values = append(values, v.data)
			}
		}

		out.items = append(out.items, Attribute{OID: oid, Values: values})
	}

	return out, nil
}

// parsePrivateKeyUsagePeriod decodes the PrivateKeyUsagePeriod extension
// (RFC 3280, 2.5.29.16): SEQUENCE { notBefore [0] IMPLICIT GeneralizedTime
// OPTIONAL, notAfter [1] IMPLICIT GeneralizedTime OPTIONAL }. A missing bound
// is the zero time.
func parsePrivateKeyUsagePeriod(value []byte) (from, to time.Time, err error) {
	seq, rest, err := derNext(value)
	if err != nil || seq.tag != 0x30 || len(rest) != 0 {
		return time.Time{}, time.Time{}, errDER
	}
	b := seq.data
	lastTag := -1
	for len(b) > 0 {
		var e derElem
		if e, b, err = derNext(b); err != nil {
			return time.Time{}, time.Time{}, err
		}
		// Primitive or constructed context tags 0 and 1, in order.
		n := int(e.tag & 0x1F)
		if e.tag&0xC0 != 0x80 || n > 1 || n <= lastTag {
			return time.Time{}, time.Time{}, errDER
		}
		lastTag = n
		t, err := parseGeneralizedTime(e.data)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		if n == 0 {
			from = t
		} else {
			to = t
		}
	}
	return from, to, nil
}

// parseGeneralizedTime parses "YYYYMMDDHHMMSS[.fff]Z" as RFC 5280 requires.
func parseGeneralizedTime(b []byte) (time.Time, error) {
	s := string(b)
	if len(s) < 15 || s[len(s)-1] != 'Z' {
		return time.Time{}, errDER
	}
	t, err := time.Parse("20060102150405Z0700", s)
	if err != nil {
		return time.Time{}, errDER
	}
	return t.UTC(), nil
}
