//go:build (linux || darwin) && cgo

package gocades

import (
	"errors"
	"testing"
)

func TestClosedCertificate(t *testing.T) {
	c := &Certificate{}

	if _, err := c.Thumbprint(); !errors.Is(err, ErrClosed) {
		t.Errorf("Thumbprint: got %v, want ErrClosed", err)
	}
	if _, err := c.ExportDER(); !errors.Is(err, ErrClosed) {
		t.Errorf("ExportDER: got %v, want ErrClosed", err)
	}
	if err := c.SetPIN("12345678"); !errors.Is(err, ErrClosed) {
		t.Errorf("SetPIN: got %v, want ErrClosed", err)
	}
	if _, err := c.ValidTo(); !errors.Is(err, ErrClosed) {
		t.Errorf("ValidTo: got %v, want ErrClosed", err)
	}
	if c.HasPrivateKey() {
		t.Error("HasPrivateKey on a closed certificate returned true")
	}

	sd := NewSignedData()
	defer sd.Close()
	sd.SetContent([]byte("x"))
	if _, err := sd.SignCades(c, CadesBES, true); !errors.Is(err, ErrClosed) {
		t.Errorf("SignCades: got %v, want ErrClosed", err)
	}
	if _, err := NewRawSignature().SignHash(c, NewHashedData()); !errors.Is(err, ErrClosed) {
		t.Errorf("RawSignature.SignHash: got %v, want ErrClosed", err)
	}

	c.Close()
	c.Close()
}

func TestNilCertificate(t *testing.T) {
	var c *Certificate

	if _, err := c.Thumbprint(); !errors.Is(err, ErrNilCertificate) {
		t.Errorf("Thumbprint: got %v, want ErrNilCertificate", err)
	}
	if c.HasPrivateKey() {
		t.Error("HasPrivateKey on nil returned true")
	}
	c.Close()

	sd := NewSignedData()
	defer sd.Close()
	sd.SetContent([]byte("x"))
	if _, err := sd.SignCades(nil, CadesBES, true); !errors.Is(err, ErrNilCertificate) {
		t.Errorf("SignCades(nil): got %v, want ErrNilCertificate", err)
	}
}

func TestUnopenedStore(t *testing.T) {
	s := NewStore()

	if _, err := s.Certificates(); !errors.Is(err, ErrClosed) {
		t.Errorf("Certificates: got %v, want ErrClosed", err)
	}
	if err := s.Add(&Certificate{}); !errors.Is(err, ErrClosed) {
		t.Errorf("Add: got %v, want ErrClosed", err)
	}

	s.Close()
	s.Close()

	var nilStore *Store
	nilStore.Close()
}

func TestClosedStoreAsOptional(t *testing.T) {
	if h, err := optionalStoreHandle(nil); h != nil || err != nil {
		t.Errorf("nil store: got (%v, %v), want (nil, nil)", h, err)
	}
	if _, err := optionalStoreHandle(NewStore()); !errors.Is(err, ErrClosed) {
		t.Errorf("unopened store: got %v, want ErrClosed", err)
	}
}

func TestClosedSymmetric(t *testing.T) {
	s, err := NewSymmetricAlgorithm()
	if err != nil {
		t.Skipf("no CSP: %v", err)
	}
	s.Close()
	s.Close()

	if err := s.GenerateKey(EncryptionGOST28147); !errors.Is(err, ErrClosed) {
		t.Errorf("GenerateKey: got %v, want ErrClosed", err)
	}
	if _, err := s.Encrypt([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Errorf("Encrypt: got %v, want ErrClosed", err)
	}
}
