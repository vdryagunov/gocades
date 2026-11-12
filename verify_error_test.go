package gocades

import (
	"errors"
	"strings"
	"testing"
)

func TestVerifyErr(t *testing.T) {
	if err := verifyErr("op", 0, 0, VerifySuccess); err != nil {
		t.Fatalf("success: got %v", err)
	}

	cases := []struct {
		name         string
		code, status int32
		wantStatus   int32
		wantUnwrap   bool
	}{
		{"status only", 0, VerifyBadSignature, VerifyBadSignature, false},
		{"code and status", hr(0x800B010A), VerifyNoChain, VerifyNoChain, true},
		// The call failed while CAdES claimed success: the status must not
		// read as valid.
		{"code with success status", hrNTEBadSignature, VerifySuccess, VerifyFailed, true},
		{"no info", hr(0x8009200E), VerifyFailed, VerifyFailed, true},
	}
	for _, c := range cases {
		err := verifyErr("op", 1, c.code, c.status)
		var ve *VerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("%s: got %v, want *VerifyError", c.name, err)
		}
		if ve.Status != c.wantStatus || ve.Signer != 1 || ve.Code != c.code {
			t.Errorf("%s: got %+v", c.name, ve)
		}
		var he *Error
		if got := errors.As(err, &he); got != c.wantUnwrap {
			t.Errorf("%s: errors.As(*Error) = %v, want %v", c.name, got, c.wantUnwrap)
		}
		if !strings.Contains(err.Error(), VerifyStatusText(c.wantStatus)) {
			t.Errorf("%s: %q lacks the status text", c.name, err)
		}
	}
}

func TestVerifyMalformedCMS(t *testing.T) {
	junk := []byte("not a CMS")

	sd := NewSignedData()
	defer sd.Close()
	sd.SetContent([]byte("content"))

	for name, verify := range map[string]func() (VerificationInfo, error){
		"VerifyCades": func() (VerificationInfo, error) { return sd.VerifyCades(junk, CadesBES, true) },
		"Verify":      func() (VerificationInfo, error) { return sd.Verify(junk, true) },
	} {
		info, err := verify()
		info.Close()
		var ve *VerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("%s: got %v, want *VerifyError", name, err)
		}
		if info.Valid || info.Status == VerifySuccess || info.Status != ve.Status {
			t.Errorf("%s: info status %d valid=%v, error status %d", name, info.Status, info.Valid, ve.Status)
		}
		signers := sd.Signers().All()
		if len(signers) != 1 || signers[0].SignatureStatus.IsValid || signers[0].SignatureStatus.Err == nil {
			t.Errorf("%s: signers %+v", name, signers)
		}
	}

	var ve *VerifyError
	if err := VerifyDetached(junk, []byte("content"), CadesBES); !errors.As(err, &ve) {
		t.Fatalf("VerifyDetached: got %v, want *VerifyError", err)
	}
}
