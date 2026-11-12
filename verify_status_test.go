package gocades

import "testing"

func TestVerifyStatusText(t *testing.T) {
	if got := VerifyStatusText(VerifySuccess); got != "signature is valid" {
		t.Fatalf("success = %q", got)
	}
	if got := VerifyStatusText(VerifyBadSignature); got != "signature value is invalid" {
		t.Fatalf("bad signature = %q", got)
	}
	if got := VerifyStatusText(VerifyFailed); got != "verification failed" {
		t.Fatalf("failed = %q", got)
	}
	if got := VerifyStatusText(0x7FFF); got != "verification failed with an unknown status" {
		t.Fatalf("unknown = %q", got)
	}
	for code := range verifyStatusText {
		if VerifyStatusText(code) == "" {
			t.Fatalf("empty text for %#x", code)
		}
	}
}
