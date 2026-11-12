//go:build (linux || darwin) && cgo

package gocades

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestCertFindTypeString(t *testing.T) {
	cases := map[CertFindType]string{
		FindBySHA1Hash:          "SHA1_HASH",
		FindBySubjectName:       "SUBJECT_NAME",
		FindByIssuerName:        "ISSUER_NAME",
		FindByRootName:          "ROOT_NAME",
		FindByTemplateName:      "TEMPLATE_NAME",
		FindByExtension:         "EXTENSION",
		FindByExtendedProperty:  "EXTENDED_PROPERTY",
		FindByApplicationPolicy: "APPLICATION_POLICY",
		FindByCertificatePolicy: "CERTIFICATE_POLICY",
		FindByTimeValid:         "TIME_VALID",
		FindByTimeNotYetValid:   "TIME_NOT_YET_VALID",
		FindByTimeExpired:       "TIME_EXPIRED",
		FindByKeyUsage:          "KEY_USAGE",
		CertFindType(99):        "UNKNOWN",
	}
	for typ, want := range cases {
		if got := typ.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", typ, got, want)
		}
	}
}

func TestNormalizeHex(t *testing.T) {
	got := normalizeHex("Aa:Bb Cc-Dd")
	if got != "aabbccdd" {
		t.Fatalf("normalizeHex = %q", got)
	}
}

func TestContainsFold(t *testing.T) {
	if !containsFold("CN=Test User", "test") {
		t.Fatal("expected match")
	}
	if containsFold("CN=Test", "other") {
		t.Fatal("unexpected match")
	}
	if !containsFold("anything", "") {
		t.Fatal("empty needle matches")
	}
}

func TestParseKeyUsageBits(t *testing.T) {
	bits, err := parseKeyUsageBits("0x3")
	if err != nil || bits != KeyUsageDigitalSignature|KeyUsageNonRepudiation {
		t.Fatalf("numeric: bits=%#x err=%v", bits, err)
	}
	bits, err = parseKeyUsageBits("digitalSignature, nonRepudiation, contentCommitment")
	if err != nil || bits != KeyUsageDigitalSignature|KeyUsageNonRepudiation {
		t.Fatalf("names: bits=%#x err=%v", bits, err)
	}
	for _, name := range []string{
		"keyEncipherment", "dataEncipherment", "keyAgreement",
		"keyCertSign", "crlSign", "encipherOnly", "decipherOnly",
	} {
		if _, err := parseKeyUsageBits(name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := parseKeyUsageBits(""); err == nil {
		t.Fatal("empty: want error")
	}
	if _, err := parseKeyUsageBits("noSuchUsage"); err == nil {
		t.Fatal("unknown: want error")
	}
}

func TestValidAt(t *testing.T) {
	der, err := os.ReadFile("testdata/gost2012-256.cer")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ImportCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	from, err := c.ValidFrom()
	if err != nil {
		t.Fatal(err)
	}
	to, err := c.ValidTo()
	if err != nil {
		t.Fatal(err)
	}
	if !validAt(c, from.Add(time.Second)) {
		t.Fatal("mid-validity should match")
	}
	if validAt(c, from.Add(-time.Hour)) {
		t.Fatal("before ValidFrom should not match")
	}
	if validAt(c, to.Add(time.Hour)) {
		t.Fatal("after ValidTo should not match")
	}
}

func TestStoreFindAndFirst(t *testing.T) {
	der, err := os.ReadFile("testdata/gost2012-256.cer")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ImportCertificateDER(der)
	if err != nil {
		t.Fatal(err)
	}
	defer cert.Close()

	st, err := OpenStore(StoreMemory, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Add(cert); err != nil {
		t.Fatal(err)
	}

	tp, err := cert.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	subj, err := cert.SubjectName()
	if err != nil {
		t.Fatal(err)
	}

	found, err := st.Find(FindBySHA1Hash, strings.ToUpper(tp[:4])+":"+tp[4:], true)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCerts(found)
	if len(found) != 1 {
		t.Fatalf("FindBySHA1Hash: got %d", len(found))
	}

	needle := "gocades-test"
	if !containsFold(subj, needle) {
		t.Fatalf("fixture subject %q does not contain %q", subj, needle)
	}
	bySubj, err := st.Find(FindBySubjectName, needle, false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCerts(bySubj)
	if len(bySubj) != 1 {
		t.Fatalf("FindBySubjectName: got %d", len(bySubj))
	}

	first, err := st.First(FindByTimeValid, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("First(FindByTimeValid) = nil")
	}
	first.Close()

	byIss, err := st.Find(FindByIssuerName, "gocades-test", false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCerts(byIss)
	if len(byIss) != 1 {
		t.Fatalf("FindByIssuerName: got %d", len(byIss))
	}

	byKU, err := st.Find(FindByKeyUsage, "digitalSignature", false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCerts(byKU)
	if len(byKU) != 1 {
		t.Fatalf("FindByKeyUsage: got %d", len(byKU))
	}

	notYet, err := st.Find(FindByTimeNotYetValid, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCerts(notYet)
	if len(notYet) != 0 {
		t.Fatalf("FindByTimeNotYetValid: got %d", len(notYet))
	}
	expired, err := st.Find(FindByTimeExpired, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeCerts(expired)
	if len(expired) != 0 {
		t.Fatalf("FindByTimeExpired: got %d", len(expired))
	}

	none, err := st.First(FindBySubjectName, "no-such-subject-xyz", false)
	if err != nil {
		t.Fatal(err)
	}
	if none != nil {
		none.Close()
		t.Fatal("expected nil First for missing subject")
	}

	if _, err := st.Find(FindByExtension, "1.2.3", false); err == nil {
		t.Fatal("unsupported find type: want error")
	}
	if _, err := st.Find(FindByKeyUsage, "notAUsage", false); err == nil {
		t.Fatal("bad key usage: want error")
	}
}

func closeCerts(certs []*Certificate) {
	for _, c := range certs {
		c.Close()
	}
}
