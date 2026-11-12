//go:build (linux || darwin) && cgo

package gocades

import (
	"encoding/asn1"
	"fmt"
	"testing"
	"time"
)

func TestX509EnrollmentCreateRequest(t *testing.T) {
	name := fmt.Sprintf("gocades-enroll-%d", time.Now().UnixNano())
	key := &X509PrivateKey{
		ProviderType:  ProvGOST2012_256,
		ContainerName: name,
		KeySpec:       ATKeyExchange,
		Exportable:    true,
		Silent:        true,
		Pin:           "12345678",
	}
	if err := key.Create(); err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() {
		if err := key.Delete(); err != nil {
			t.Errorf("Delete: %v", err)
		}
	}()

	dn := &X500DistinguishedName{}
	if err := dn.Encode("CN=gocades-enroll-test,C=RU"); err != nil {
		t.Fatal(err)
	}
	req := &X509CertificateRequestPkcs10{}
	if err := req.InitializeFromPrivateKey(ContextUser, key, ""); err != nil {
		t.Fatal(err)
	}
	if err := req.SetSubject(dn); err != nil {
		t.Fatal(err)
	}
	req.SetKeyUsage(KeyUsageDigitalSignature | KeyUsageNonRepudiation)

	enroll := &X509Enrollment{Silent: true}
	if err := enroll.InitializeFromRequest(req); err != nil {
		t.Fatal(err)
	}
	der, err := enroll.CreateRequestDER()
	if err != nil {
		t.Fatalf("CreateRequestDER: %v", err)
	}
	if len(der) < 64 {
		t.Fatalf("request too short: %d", len(der))
	}
	// PKCS#10 is a SEQUENCE.
	var rest asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rest); err != nil {
		t.Fatalf("asn1: %v", err)
	}
	if rest.Tag != asn1.TagSequence {
		t.Fatalf("tag=%d, want SEQUENCE", rest.Tag)
	}

	b64, err := enroll.CreateRequest(EncodingBase64)
	if err != nil || b64 == "" {
		t.Fatalf("base64: %q %v", b64, err)
	}
}
