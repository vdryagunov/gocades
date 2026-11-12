package gocades

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

// revocationFixture is an RSA root, a leaf whose CRL distribution point is
// unreachable, and a CRL from the root that revokes the leaf. The root key
// is discarded, so trusting the root for a while grants nothing.
type revocationFixture struct {
	root, leaf, crl []byte
}

func newRevocationFixture(t *testing.T) revocationFixture {
	t.Helper()
	now := time.Now()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "gocades revocation test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(root)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: "gocades revoked leaf"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{"http://127.0.0.1:1/gocades-test.crl"},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: leafTmpl.SerialNumber, RevocationTime: now.Add(-time.Minute)},
		},
	}, rootCert, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return revocationFixture{root: root, leaf: leaf, crl: crl}
}

func TestIsValidRevocation(t *testing.T) {
	fx := newRevocationFixture(t)

	leaf, err := ImportCertificateDER(fx.leaf)
	if err != nil {
		t.Fatal(err)
	}
	defer leaf.Close()
	root, err := ImportCertificateDER(fx.root)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	extra, err := OpenStore(StoreMemory, "")
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if extra.Location() != "Memory" {
		t.Fatalf("Location() = %q", extra.Location())
	}

	// Store.Remove on the memory store.
	if err := extra.Add(root); err != nil {
		t.Fatal(err)
	}
	if err := extra.Remove(root); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if certs, err := extra.Certificates(); err != nil || len(certs) != 0 {
		t.Fatalf("after Remove: %d certificates, %v", len(certs), err)
	}
	var e *Error
	if err := extra.Remove(root); !errors.As(err, &e) {
		t.Fatalf("second Remove: got %v, want *Error", err)
	}
	if _, err := root.Thumbprint(); err != nil {
		t.Fatalf("certificate unusable after Remove: %v", err)
	}
	if err := extra.Add(root); err != nil {
		t.Fatal(err)
	}
	leaf.AdditionalStore(extra)

	// Opt-in: this changes the machine trust store for the test's duration.
	trusted := os.Getenv("GOCADES_TEST_MROOT") == "1"
	if trusted {
		mroot, err := OpenStore(StoreLocalMachine, "Root")
		if err != nil {
			t.Fatal(err)
		}
		defer mroot.Close()
		if err := mroot.Add(root); err != nil {
			t.Fatalf("adding the test root to mRoot: %v", err)
		}
		// Store.Add must commit at once: the chain engine reads mRoot from
		// disk, and CryptoPro would otherwise write it only on Close.
		m2, err := OpenStore(StoreLocalMachine, "Root")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha1.Sum(fx.root)
		found, err := m2.FindBySHA1(sum[:])
		m2.Close()
		if err != nil {
			t.Fatalf("test root not visible through a second mRoot handle: %v", err)
		}
		found.Close()
		defer func() {
			if err := mroot.Remove(root); err != nil {
				t.Errorf("removing the test root from mRoot: %v", err)
			}
		}()
	}

	const revBits = ChainRevoked | ChainRevocationUnknown | ChainOfflineRevocation
	check := func(name string, opts ValidateOptions) CertificateStatus {
		t.Helper()
		st, err := leaf.IsValidWith(opts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: result=%v policy=%s chain=%#x", name, st.Result,
			ErrorText(st.PolicyError), st.ChainStatus)
		if st.Result != (opts.Revocation == RevocationNone && trusted) {
			t.Errorf("%s: Result = %v", name, st.Result)
		}
		return st
	}

	if _, err := leaf.IsValidWith(ValidateOptions{Revocation: 7}); err == nil {
		t.Error("unknown revocation mode accepted")
	}
	if _, err := leaf.IsValidWith(ValidateOptions{URLTimeout: -time.Second}); err == nil {
		t.Error("negative URL timeout accepted")
	}

	if !trusted {
		if st := check("untrusted, no revocation", ValidateOptions{Revocation: RevocationNone}); st.ChainStatus&ChainUntrustedRoot == 0 {
			t.Errorf("chain %#x, want ChainUntrustedRoot", st.ChainStatus)
		}
		// CryptoPro skips revocation for an untrusted chain.
		t.Skip("set GOCADES_TEST_MROOT=1 to trust a throwaway root in mRoot")
	}

	if st := check("no revocation", ValidateOptions{Revocation: RevocationNone}); st.ChainStatus != 0 || st.PolicyError != 0 {
		t.Fatalf("trusted chain without revocation: chain %#x, policy %#x; want clean",
			st.ChainStatus, st.PolicyError)
	}
	if st := check("online, unreachable CDP", ValidateOptions{URLTimeout: 3 * time.Second}); st.ChainStatus&ChainRevocationUnknown == 0 {
		t.Errorf("chain %#x, want ChainRevocationUnknown", st.ChainStatus)
	}
	if st := check("cache only, no CRL", ValidateOptions{Revocation: RevocationCacheOnly}); st.ChainStatus&revBits == 0 {
		t.Errorf("chain %#x, want a revocation bit", st.ChainStatus)
	}

	if err := extra.AddCRL(fx.crl); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		name string
		rev  Revocation
	}{{"cache only, CRL in store", RevocationCacheOnly}, {"online, CRL in store", RevocationOnline}} {
		if st := check(mode.name, ValidateOptions{Revocation: mode.rev, URLTimeout: 3 * time.Second}); st.ChainStatus&ChainRevoked == 0 {
			t.Errorf("%s: chain %#x, want ChainRevoked", mode.name, st.ChainStatus)
		}
	}
}
