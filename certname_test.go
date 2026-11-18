//go:build (linux || darwin) && cgo

package gocades

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestSubjectIssuerNamesDistinct(t *testing.T) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gocades-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "gocades-test-leaf"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ImportCertificateDER(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()

	subj, err := cert.SubjectName()
	if err != nil {
		t.Fatal(err)
	}
	iss, err := cert.IssuerName()
	if err != nil {
		t.Fatal(err)
	}
	if subj == "" || iss == "" {
		t.Fatalf("empty names: subject=%q issuer=%q", subj, iss)
	}
	if subj == iss {
		t.Fatalf("SubjectName == IssuerName == %q (ISSUER_FLAG likely OR'd into dwType)", subj)
	}
	if got, err := cert.Info(CertInfoSubjectSimpleName); err != nil || got != subj {
		t.Fatalf("Info(SubjectSimple)=%q %v, want %q", got, err, subj)
	}
	if got, err := cert.Info(CertInfoIssuerSimpleName); err != nil || got != iss {
		t.Fatalf("Info(IssuerSimple)=%q %v, want %q", got, err, iss)
	}
}
