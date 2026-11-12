package gocades

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestAbout(t *testing.T) {
	var a About
	name, err := a.CSPName(ProvGOST2012_256)
	if err != nil || name == "" {
		t.Fatalf("CSPName(80) = %q, %v", name, err)
	}
	t.Logf("CSPName(80) = %q", name)

	def, err := a.CSPVersion()
	if err != nil {
		t.Fatalf("CSPVersion: %v", err)
	}
	named, err := a.CSPVersionOf(name, ProvGOST2012_256)
	if err != nil {
		t.Fatalf("CSPVersionOf(%q): %v", name, err)
	}
	if def.Major == 0 || def != named {
		t.Fatalf("CSPVersion %v, CSPVersionOf %v; want equal and non-zero", def, named)
	}

	var e *Error
	if _, err := a.CSPName(0x7FFF); !errors.As(err, &e) {
		t.Fatalf("CSPName(unknown type) = %v, want *Error", err)
	}
	if _, err := a.CSPVersionOf("no such provider", ProvGOST2012_256); !errors.As(err, &e) {
		t.Fatalf("CSPVersionOf(unknown name) = %v, want *Error", err)
	}
}

func TestExtensionsMatchX509(t *testing.T) {
	der, err := os.ReadFile("testdata/gost2012-256.cer")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ImportCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()

	exts, err := cert.Extensions()
	if err != nil {
		t.Fatal(err)
	}
	if exts.Count() != len(ref.Extensions) || exts.Count() == 0 {
		t.Fatalf("Count = %d, crypto/x509 sees %d", exts.Count(), len(ref.Extensions))
	}
	for i, want := range ref.Extensions {
		got, err := exts.Item(i)
		if err != nil {
			t.Fatal(err)
		}
		if got.OID.Value != want.Id.String() || got.IsCritical != want.Critical ||
			!bytes.Equal(got.EncodedData.Value(), want.Value) {
			t.Errorf("extension %d: got %s critical=%v %d bytes; want %s critical=%v %d bytes",
				i, got.OID.Value, got.IsCritical, len(got.EncodedData.Value()),
				want.Id, want.Critical, len(want.Value))
		}
	}
	if _, err := exts.Item(exts.Count()); err == nil {
		t.Error("Item past the end accepted")
	}

	var e *Error
	if _, err := cert.PrivateKeyUsagePeriodFrom(); !errors.As(err, &e) || e.Code != hrCryptENotFound {
		t.Fatalf("PrivateKeyUsagePeriodFrom without the extension = %v, want CRYPT_E_NOT_FOUND", err)
	}
}

func TestPrivateKeyUsagePeriodCert(t *testing.T) {
	from := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	to := time.Date(2027, 6, 7, 8, 9, 10, 0, time.UTC)
	type period struct {
		NotBefore time.Time `asn1:"optional,tag:0,generalized"`
		NotAfter  time.Time `asn1:"optional,tag:1,generalized"`
	}
	val, err := asn1.Marshal(period{from, to})
	if err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "gocades PKUP test"},
		NotBefore:    from,
		NotAfter:     to.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 16}, Value: val},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ImportCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()

	if got, err := cert.PrivateKeyUsagePeriodFrom(); err != nil || !got.Equal(from) {
		t.Fatalf("From = %v, %v; want %v", got, err, from)
	}
	if got, err := cert.PrivateKeyUsagePeriodTo(); err != nil || !got.Equal(to) {
		t.Fatalf("To = %v, %v; want %v", got, err, to)
	}
	exts, err := cert.Extensions()
	if err != nil {
		t.Fatal(err)
	}
	if x, ok := exts.Find(OIDPrivateKeyUsagePeriod); !ok || x.IsCritical {
		t.Fatalf("Find(2.5.29.16) = %+v, %v", x, ok)
	}
}

func TestParsePrivateKeyUsagePeriod(t *testing.T) {
	gt := func(tag byte, s string) []byte { return append([]byte{tag, byte(len(s))}, s...) }
	seq := func(parts ...[]byte) []byte {
		body := bytes.Join(parts, nil)
		return append([]byte{0x30, byte(len(body))}, body...)
	}
	from := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)

	cases := []struct {
		name     string
		in       []byte
		from, to time.Time
		bad      bool
	}{
		{"both", seq(gt(0x80, "20251231235959Z"), gt(0x81, "20261231235959Z")), from, from.AddDate(1, 0, 0), false},
		{"only notAfter", seq(gt(0x81, "20251231235959Z")), time.Time{}, from, false},
		{"fraction", seq(gt(0x80, "20251231235959.5Z")), from.Add(500 * time.Millisecond), time.Time{}, false},
		{"empty", seq(), time.Time{}, time.Time{}, false},
		{"wrong order", seq(gt(0x81, "20251231235959Z"), gt(0x80, "20251231235959Z")), time.Time{}, time.Time{}, true},
		{"local time", seq(gt(0x80, "20251231235959")), time.Time{}, time.Time{}, true},
		{"UTCTime tag", seq(gt(0x17, "251231235959Z")), time.Time{}, time.Time{}, true},
		{"trailing bytes", append(seq(), 0), time.Time{}, time.Time{}, true},
		{"not a sequence", gt(0x80, "20251231235959Z"), time.Time{}, time.Time{}, true},
	}
	for _, c := range cases {
		f, to, err := parsePrivateKeyUsagePeriod(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("%s: accepted", c.name)
			}
			continue
		}
		if err != nil || !f.Equal(c.from) || !to.Equal(c.to) {
			t.Errorf("%s: got %v, %v, %v; want %v, %v", c.name, f, to, err, c.from, c.to)
		}
	}
}

func TestMsgTypeRejectsGarbage(t *testing.T) {
	var e *Error
	if _, err := GetMsgType(nil); !errors.As(err, &e) {
		t.Fatalf("GetMsgType(nil) = %v", err)
	}
	if _, err := GetMsgType([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); !errors.As(err, &e) {
		t.Fatalf("GetMsgType(garbage) = %v", err)
	}
	if _, err := IsMsgType([]byte("not a cms"), CadesBES); !errors.As(err, &e) {
		t.Fatalf("IsMsgType(garbage) = %v", err)
	}
}
