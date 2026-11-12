package gocades

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

/* ------------------------------------------------------------------ */
/* DER encoders used only by the tests                                 */
/* ------------------------------------------------------------------ */

func encLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xFF)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func encTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encLen(len(content))...)
	return append(out, content...)
}

func encCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func encSeq(parts ...[]byte) []byte { return encTLV(0x30, encCat(parts...)) }
func encSet(parts ...[]byte) []byte { return encTLV(0x31, encCat(parts...)) }

func encInt(v int) []byte {
	if v == 0 {
		return encTLV(0x02, []byte{0})
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v & 0xFF)}, b...)
		v >>= 8
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return encTLV(0x02, b)
}

func encOID(s string) []byte {
	parts := strings.Split(s, ".")
	first, _ := strconv.Atoi(parts[0])
	second, _ := strconv.Atoi(parts[1])

	out := []byte{byte(first*40 + second)}
	for _, p := range parts[2:] {
		v, _ := strconv.Atoi(p)

		var enc []byte
		enc = append(enc, byte(v&0x7F))
		v >>= 7
		for v > 0 {
			enc = append(enc, byte(v&0x7F)|0x80)
			v >>= 7
		}
		for i := len(enc) - 1; i >= 0; i-- {
			out = append(out, enc[i])
		}
	}
	return encTLV(0x06, out)
}

func encOctet(b ...byte) []byte { return encTLV(0x04, b) }

// buildTestCMS assembles a minimal SignedData with one signer that carries two
// signed attributes and one unsigned attribute.
func buildTestCMS() []byte {
	attr := func(oid string, values ...[]byte) []byte {
		return encSeq(encOID(oid), encSet(values...))
	}

	signedAttrs := encTLV(0xA0, encCat(
		attr("1.2.840.113549.1.9.3", encOID("1.2.840.113549.1.7.1")),
		attr("1.2.840.113549.1.9.4", encOctet(0xAA, 0xBB)),
	))
	unsignedAttrs := encTLV(0xA1, encCat(
		attr("1.2.840.113549.1.9.16.2.14", encSeq(encOID("1.2.840.113549.1.9.16.1.4"))),
	))

	signerInfo := encSeq(
		encInt(1),
		encSeq(),
		encSeq(encOID("1.2.643.7.1.1.2.2")),
		signedAttrs,
		encSeq(encOID("1.2.643.7.1.1.1.1")),
		encOctet(0x01, 0x02),
		unsignedAttrs,
	)

	signedData := encSeq(
		encInt(1),
		encSet(),
		encSeq(),
		encSet(signerInfo),
	)

	return encSeq(
		encOID("1.2.840.113549.1.7.2"),
		encTLV(0xA0, signedData),
	)
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

func TestParseCMSSignerInfos(t *testing.T) {
	infos, err := ParseCMSSignerInfos(buildTestCMS())
	if err != nil {
		t.Fatalf("ParseCMSSignerInfos: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("got %d signers, want 1", len(infos))
	}

	signed := infos[0].SignedAttributes
	if got := signed.Count(); got != 2 {
		t.Fatalf("signed attributes = %d, want 2", got)
	}

	contentType, ok := signed.Find("1.2.840.113549.1.9.3")
	if !ok {
		t.Fatal("contentType attribute not found")
	}
	oid, err := derOID(contentType.Value())
	if err != nil {
		t.Fatalf("decode contentType value: %v", err)
	}
	if oid != "1.2.840.113549.1.7.1" {
		t.Fatalf("contentType = %q, want 1.2.840.113549.1.7.1", oid)
	}

	digest, ok := signed.Find("1.2.840.113549.1.9.4")
	if !ok {
		t.Fatal("messageDigest attribute not found")
	}
	if !bytes.Equal(digest.Value(), []byte{0xAA, 0xBB}) {
		t.Fatalf("messageDigest = %x, want aabb", digest.Value())
	}

	unsigned := infos[0].UnsignedAttributes
	if got := unsigned.Count(); got != 1 {
		t.Fatalf("unsigned attributes = %d, want 1", got)
	}
	if _, ok := unsigned.Find("1.2.840.113549.1.9.16.2.14"); !ok {
		t.Fatal("signatureTimeStampToken attribute not found")
	}
}

func TestParseCMSSignerInfosRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":       nil,
		"truncated":   {0x30, 0x05, 0x06, 0x03},
		"not a SEQ":   {0x31, 0x00},
		"wrong oid":   encSeq(encOID("1.2.840.113549.1.7.1"), encTLV(0xA0, encSeq())),
		"no [0] body": encSeq(encOID("1.2.840.113549.1.7.2")),
	}

	for name, in := range cases {
		if _, err := ParseCMSSignerInfos(in); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestDEROIDRoundTrip(t *testing.T) {
	for _, s := range []string{
		"1.2.840.113549.1.7.2",
		"1.2.643.7.1.1.2.2",
		"2.5.29.15",
		"1.3.6.1.5.5.7.48.1.1",
	} {
		elem, err := derChildren(encOID(s))
		if err != nil {
			t.Fatalf("%s: parse: %v", s, err)
		}
		got, err := derOID(elem[0].data)
		if err != nil {
			t.Fatalf("%s: decode: %v", s, err)
		}
		if got != s {
			t.Fatalf("round trip = %q, want %q", got, s)
		}
	}
}

func TestDEROIDLargeArcs(t *testing.T) {
	cases := map[string][]byte{
		// 2.999.3: first subidentifier 80+999 = 1079 spans two bytes.
		"2.999.3": {0x88, 0x37, 0x03},
		// 2.25 with a 128-bit UUID arc, beyond int64.
		"2.25.329800735698586629295641978511506172918": {
			0x69, 0x83, 0xF0, 0x9D, 0xA7, 0xEB, 0xCF, 0xDE, 0xE0, 0xC7,
			0xA1, 0xA7, 0xB2, 0xC0, 0x94, 0x8C, 0xC8, 0xF9, 0xD7, 0x76,
		},
		"0.39":  {0x27},
		"1.0.5": {0x28, 0x05},
	}
	for want, enc := range cases {
		got, err := derOID(enc)
		if err != nil || got != want {
			t.Errorf("derOID(% x) = %q, %v; want %q", enc, got, err, want)
		}
	}

	for name, enc := range map[string][]byte{
		"truncated":   {0x2A, 0x86},
		"non-minimal": {0x2A, 0x80, 0x01},
		"empty":       {},
	} {
		if _, err := derOID(enc); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// toIndefinite re-encodes the outer constructed TLV of der with the BER
// indefinite length.
func toIndefinite(t *testing.T, der []byte) []byte {
	t.Helper()
	e, rest, err := derNext(der)
	if err != nil || len(rest) != 0 || e.tag&0x20 == 0 {
		t.Fatalf("not a single constructed TLV: %v", err)
	}
	out := []byte{e.tag, 0x80}
	out = append(out, e.data...)
	return append(out, 0, 0)
}

func TestParseCMSSignerInfosBER(t *testing.T) {
	der := buildTestCMS()

	// Indefinite length on the outer ContentInfo and on the inner
	// SignedData SEQUENCE, as streamed CMS encoders write it.
	top, _, _ := derNext(der)
	ci, _ := derChildren(top.data)
	wrapped, _ := derChildren(ci[1].data)
	inner := toIndefinite(t, encTLV(wrapped[0].tag, wrapped[0].data))
	ber := toIndefinite(t, encSeq(encTLV(ci[0].tag, ci[0].data), encTLV(0xA0, inner)))

	infos, err := ParseCMSSignerInfos(ber)
	if err != nil {
		t.Fatalf("BER CMS: %v", err)
	}
	if len(infos) != 1 || infos[0].SignedAttributes.Count() != 2 {
		t.Fatalf("BER CMS: got %+v", infos)
	}

	if _, err := ParseCMSSignerInfos([]byte{0x30, 0x80, 0x02, 0x01, 0x01}); err == nil {
		t.Error("missing end-of-contents: expected an error")
	}
	if _, err := ParseCMSSignerInfos([]byte{0x04, 0x80, 0x00, 0x00}); err == nil {
		t.Error("indefinite primitive: expected an error")
	}
	deep := bytes.Repeat([]byte{0x30, 0x80}, maxBERDepth+2)
	if _, err := ParseCMSSignerInfos(deep); err == nil {
		t.Error("deep nesting: expected an error")
	}
}

func TestParseAttributesRejectsMalformed(t *testing.T) {
	for name, in := range map[string][]byte{
		"not a SEQUENCE": encSet(encOctet(1)),
		"no type":        encSeq(encOctet(1), encSet()),
		"bad OID":        encSeq(encTLV(0x06, []byte{0x2A, 0x86}), encSet()),
	} {
		if _, err := parseAttributes(in); err == nil {
			t.Errorf("%s: expected an error, attribute would be dropped silently", name)
		}
	}
}

func FuzzParseCMSSignerInfos(f *testing.F) {
	f.Add(buildTestCMS())
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Add([]byte{0x06, 0x03, 0x88, 0x37, 0x03})
	f.Fuzz(func(t *testing.T, b []byte) {
		infos, err := ParseCMSSignerInfos(b)
		if err != nil && infos != nil {
			t.Fatal("result together with an error")
		}
	})
}

func TestDERLongFormLength(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 300)
	elems, err := derChildren(encOctet(payload...))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(elems) != 1 || !bytes.Equal(elems[0].data, payload) {
		t.Fatal("long-form length was not decoded correctly")
	}
}

func TestBlobs(t *testing.T) {
	var b Blobs
	b.Add([]byte{1, 2})
	b.Add([]byte{3})

	if b.Count() != 2 {
		t.Fatalf("Count = %d, want 2", b.Count())
	}
	if v, err := b.Item(0); err != nil || !bytes.Equal(v, []byte{1, 2}) {
		t.Fatalf("Item(0) = %x, %v", v, err)
	}
	if _, err := b.Item(2); err == nil {
		t.Fatal("Item(2) should be out of range")
	}

	b.Clear()
	if b.Count() != 0 {
		t.Fatal("Clear did not empty the collection")
	}
}
