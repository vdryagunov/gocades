//go:build (linux || darwin) && cgo

package gocades

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"hash"
	"os"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hashWith(t *testing.T, alg HashAlg, key, data []byte) []byte {
	t.Helper()
	hd := NewHashedData()
	hd.SetAlgorithm(alg)
	hd.SetKey(key)
	if err := hd.Hash(data); err != nil {
		t.Fatalf("%v: %v", alg, err)
	}
	return hd.Value()
}

// The empty-message digests fix the byte order returned by the CSP.
func TestStreebogEmpty(t *testing.T) {
	for alg, want := range map[HashAlg]string{
		HashAlgGOST3411_2012_256: "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
		HashAlgGOST3411_2012_512: "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7" +
			"362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
	} {
		if got := hex.EncodeToString(hashWith(t, alg, nil, nil)); got != want {
			t.Errorf("%v(\"\") = %s, want %s", alg, got, want)
		}
	}
}

// RFC 7836, section 4.1.
func TestHMACRFC7836(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	data := mustHex(t, "0126bdb87800af214341456563780100")

	for alg, want := range map[HashAlg]string{
		HashAlgGOST3411_2012_256_HMAC: "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9",
		HashAlgGOST3411_2012_512_HMAC: "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77" +
			"3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6",
	} {
		if got := hex.EncodeToString(hashWith(t, alg, key, data)); got != want {
			t.Errorf("%v = %s, want %s", alg, got, want)
		}
	}
}

// The hand-written HMAC must agree with crypto/hmac over the same digests,
// including keys longer than the block and the 32-byte block of 34.11-94.
func TestHMACMatchesStdlib(t *testing.T) {
	cases := []struct {
		alg  HashAlg
		base func() hash.Hash
	}{
		{HashAlgGOST3411_2012_256_HMAC, NewGOST3411_2012_256},
		{HashAlgGOST3411_2012_512_HMAC, NewGOST3411_2012_512},
		{HashAlgGOST3411HMAC, NewGOST3411},
	}
	data := []byte("The quick brown fox jumps over the lazy dog")

	for _, c := range cases {
		for _, n := range []int{1, 32, 33, 64, 65, 200} {
			key := bytes.Repeat([]byte{0xA5}, n)
			mac := hmac.New(c.base, key)
			mac.Write(data)
			if got, want := hashWith(t, c.alg, key, data), mac.Sum(nil); !bytes.Equal(got, want) {
				t.Errorf("%v key=%d bytes: got %x, want %x", c.alg, n, got, want)
			}
		}
	}
}

func TestHMACRequiresKey(t *testing.T) {
	hd := NewHashedData()
	hd.SetAlgorithm(HashAlgGOST3411_2012_256_HMAC)
	err := hd.Hash([]byte("x"))
	var e *Error
	if !errors.As(err, &e) || e.Code != hrEInvalidArg {
		t.Fatalf("HMAC without a key: got %v, want E_INVALIDARG", err)
	}
}

func TestPlainDigestIgnoresKey(t *testing.T) {
	data := []byte("data")
	plain := hashWith(t, HashAlgGOST3411_2012_256, nil, data)
	keyed := hashWith(t, HashAlgGOST3411_2012_256, []byte("key"), data)
	if !bytes.Equal(plain, keyed) {
		t.Fatal("a key changed a plain digest")
	}
}

func TestHashAlgForOID(t *testing.T) {
	if a, err := hashAlgForOID(""); err != nil || a != HashAlgGOST3411_2012_256 {
		t.Errorf("empty OID: got (%v, %v), want the 2012-256 default", a, err)
	}
	if a, err := hashAlgForOID("1.2.643.7.1.1.2.3"); err != nil || a != HashAlgGOST3411_2012_512 {
		t.Errorf("2012-512 OID: got (%v, %v)", a, err)
	}
	if _, err := hashAlgForOID("1.2.3.4"); err == nil {
		t.Error("unknown OID: got no error")
	}
}

// testdata/gost2012-256.cer is a self-signed GOST R 34.10-2012 (256 bit)
// certificate whose private key no longer exists; only public-key checks are
// possible with it.
func testGOSTCertificate(t *testing.T) *Certificate {
	t.Helper()
	der, err := os.ReadFile("testdata/gost2012-256.cer")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ImportCertificateDER(der)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestRawSignatureDigestLength(t *testing.T) {
	cert := testGOSTCertificate(t)
	rs := NewRawSignature()
	const ntBadHash int32 = -2146893822 // NTE_BAD_HASH, 0x80090002

	for _, n := range []int{16, 31, 33, 64} {
		var e *Error
		_, err := rs.SignDigest(cert, make([]byte, n))
		if !errors.As(err, &e) || e.Code != ntBadHash {
			t.Errorf("SignDigest with %d bytes: got %v, want NTE_BAD_HASH", n, err)
		}
		err = rs.VerifyDigest(cert, make([]byte, n), make([]byte, 64))
		if !errors.As(err, &e) || e.Code != ntBadHash {
			t.Errorf("VerifyDigest with %d bytes: got %v, want NTE_BAD_HASH", n, err)
		}
	}

	if err := rs.VerifyDigest(cert, make([]byte, 32), make([]byte, 64)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("VerifyDigest with a 32-byte digest and a forged signature: got %v, want ErrBadSignature", err)
	}
}
