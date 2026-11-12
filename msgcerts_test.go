//go:build (linux || darwin) && cgo

package gocades

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCRL(t *testing.T) {
	fx := newRevocationFixture(t)
	root, err := x509.ParseCertificate(fx.root)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.ParseRevocationList(fx.crl)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := ImportCRLDER(fx.crl)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := crl.IssuerName()
	if issuer != "CN=gocades revocation test root" {
		t.Errorf("IssuerName = %q", issuer)
	}
	if got, _ := crl.ThisUpdate(); !got.Equal(want.ThisUpdate.Truncate(time.Second)) {
		t.Errorf("ThisUpdate = %v, want %v", got, want.ThisUpdate)
	}
	if got, _ := crl.NextUpdate(); !got.Equal(want.NextUpdate.Truncate(time.Second)) {
		t.Errorf("NextUpdate = %v, want %v", got, want.NextUpdate)
	}
	sum := sha1.Sum(fx.crl)
	if got, _ := crl.Thumbprint(); got != strings.ToUpper(hex.EncodeToString(sum[:])) {
		t.Errorf("Thumbprint = %q", got)
	}
	if len(root.SubjectKeyId) == 0 {
		t.Fatal("fixture root has no SubjectKeyId")
	}
	if got, _ := crl.AuthKeyID(); got != strings.ToUpper(hex.EncodeToString(root.SubjectKeyId)) {
		t.Errorf("AuthKeyID = %q, want %X", got, root.SubjectKeyId)
	}

	b64, err := crl.Export(EncodingBase64)
	if err != nil {
		t.Fatal(err)
	}
	again := NewCRL()
	if err := again.Import(b64, EncodingBase64); err != nil {
		t.Fatal(err)
	}
	if der, _ := again.ExportDER(); !bytes.Equal(der, fx.crl) {
		t.Error("base64 round trip changed the CRL")
	}

	if _, err := NewCRL().IssuerName(); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("empty CRL: err = %v, want ErrNotInitialized", err)
	}
	if _, err := ImportCRLDER([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); err == nil {
		t.Error("garbage CRL imported")
	}
}

// buildXLongCMS assembles a SignedData whose certificates field holds
// certField and whose only signer (issued by the leaf's issuer) carries the
// CAdES-X Long attributes certificate-values (certValues) and
// revocation-values (crlVals). The signature itself is garbage: these tests
// only read the encoding.
func buildXLongCMS(t *testing.T, leaf []byte, certField, certValues, crlVals [][]byte) []byte {
	t.Helper()
	lc, err := x509.ParseCertificate(leaf)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := asn1.Marshal(lc.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	attr := func(oid string, values ...[]byte) []byte {
		return encSeq(encOID(oid), encSet(values...))
	}

	var unsigned []byte
	if certValues != nil || crlVals != nil {
		unsigned = encTLV(0xA1, encCat(
			attr("1.2.840.113549.1.9.16.2.23", encSeq(certValues...)),
			attr("1.2.840.113549.1.9.16.2.24", encSeq(encTLV(0xA0, encSeq(crlVals...)))),
		))
	}
	signerInfo := encSeq(
		encInt(1),
		encSeq(lc.RawIssuer, serial),
		encSeq(encOID("1.2.643.7.1.1.2.2")),
		encSeq(encOID("1.2.643.7.1.1.1.1")),
		encOctet(0x01, 0x02),
		unsigned,
	)
	signedData := encSeq(
		encInt(1),
		encSet(encSeq(encOID("1.2.643.7.1.1.2.2"))),
		encSeq(encOID("1.2.840.113549.1.7.1")),
		encTLV(0xA0, encCat(certField...)),
		encSet(signerInfo),
	)
	return encSeq(encOID("1.2.840.113549.1.7.2"), encTLV(0xA0, signedData))
}

func TestMessageCertificatesAndRevocationValues(t *testing.T) {
	fx := newRevocationFixture(t)
	other := newRevocationFixture(t)
	cms := buildXLongCMS(t, fx.leaf,
		[][]byte{fx.leaf},
		[][]byte{fx.root, fx.leaf, other.root},
		[][]byte{fx.crl})

	certs, err := MessageCertificates(cms)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, c := range certs {
			c.Close()
		}
	}()
	var got [][]byte
	for _, c := range certs {
		der, err := c.ExportDER()
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, der)
	}
	want := [][]byte{fx.leaf, fx.root, other.root}
	if len(got) != len(want) {
		t.Fatalf("got %d certificates, want %d (certificates field + certificate-values, deduplicated)", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("certificate %d differs", i)
		}
	}

	crls, ocsps, err := revocationValues(cms, 0)
	if err != nil {
		t.Fatal(err)
	}
	if crls.Count() != 1 || ocsps.Count() != 0 {
		t.Fatalf("revocation values: %d CRLs, %d OCSP responses; want 1, 0", crls.Count(), ocsps.Count())
	}
	if b, _ := crls.Item(0); !bytes.Equal(b, fx.crl) {
		t.Error("CRL differs")
	}

	// The verification fails (garbage signature), but the signer still
	// reports its evidence and SignedData remembers the message.
	sd := NewSignedData()
	defer sd.Close()
	_, verr := sd.VerifyCades(cms, CadesBES, false)
	var ve *VerifyError
	if !errors.As(verr, &ve) {
		t.Fatalf("VerifyCades: %v, want *VerifyError", verr)
	}
	sg, err := sd.Signers().Item(0)
	if err != nil {
		t.Fatal(err)
	}
	if sg.CRLs.Count() != 1 {
		t.Errorf("Signer.CRLs has %d items, want 1", sg.CRLs.Count())
	}
	all, err := sd.Certificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(want) {
		t.Errorf("SignedData.Certificates: %d, want %d", len(all), len(want))
	}
	for _, c := range all {
		c.Close()
	}

	plain := buildXLongCMS(t, fx.leaf, [][]byte{fx.leaf}, nil, nil)
	if crls, ocsps, err := revocationValues(plain, 0); err != nil || crls.Count() != 0 || ocsps.Count() != 0 {
		t.Errorf("CMS without revocation-values: %d, %d, %v", crls.Count(), ocsps.Count(), err)
	}
	if certs, err := MessageCertificates(plain); err != nil || len(certs) != 1 {
		t.Errorf("CMS without certificate-values: %d certificates, %v; want 1", len(certs), err)
	} else {
		certs[0].Close()
	}
	if _, err := MessageCertificates([]byte("not a CMS")); err == nil {
		t.Error("MessageCertificates accepted garbage")
	}
}

func TestImportPFXRejectsGarbage(t *testing.T) {
	s := NewStore()
	if err := s.ImportPFX([]byte{0x30, 0x03, 0x02, 0x01, 0x03}, "pass", 0); err == nil {
		t.Fatal("garbage PFX imported")
	}
	if _, err := s.Certificates(); !errors.Is(err, ErrClosed) {
		t.Errorf("store after a failed import: %v, want ErrClosed", err)
	}
	if err := s.ImportPFX(nil, "", 0); err == nil {
		t.Error("empty PFX imported")
	}
}
