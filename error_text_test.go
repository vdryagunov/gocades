package gocades

import (
	"strings"
	"testing"
)

// hr converts an unsigned HRESULT literal into the sign-extended int32 that
// Error.Code carries. The intermediate variable is deliberate: converting the
// constant directly would be a compile-time overflow.
func hr(code uint32) int32 {
	return int32(code)
}

func TestErrorTextKnownCode(t *testing.T) {
	got := ErrorText(0x8009000B) // NTE_BAD_KEY_STATE
	if !strings.HasPrefix(got, "NTE_BAD_KEY_STATE: ") {
		t.Fatalf("ErrorText(0x8009000B) = %q, want the NTE_BAD_KEY_STATE description", got)
	}
}

func TestErrorTextNameOnly(t *testing.T) {
	// A failure code that has a symbolic name in CSP_WinError.h but no curated
	// description must still be reported by name.
	if got := ErrorText(0x80096002); got == "" {
		t.Fatal("expected a symbolic name for 0x80096002")
	}
}

func TestErrorTextTSPClient(t *testing.T) {
	// Codes from tspcli_e.h use their own facility and are not in
	// CSP_WinError.h; the generator must pick them up too.
	for code, name := range map[uint32]string{
		0xC2100100: "TSPCLI_ERROR_HTTP",
		0xC2100140: "TSPCLI_ERROR_LicenseExpired",
	} {
		if got := ErrorText(code); !strings.HasPrefix(got, name) {
			t.Errorf("ErrorText(%#X) = %q, want prefix %q", code, got, name)
		}
	}
}

func TestErrorTextUnknownCode(t *testing.T) {
	if got := ErrorText(0x87654321); got != "" {
		t.Fatalf("ErrorText(unknown) = %q, want empty", got)
	}
}

func TestErrorMessageIncludesText(t *testing.T) {
	err := &Error{Op: "SignCades", Code: hr(0x8009000B)}
	msg := err.Error()

	if !strings.Contains(msg, "0x8009000B") {
		t.Fatalf("%q does not contain the hex code", msg)
	}
	if !strings.Contains(msg, "NTE_BAD_KEY_STATE") {
		t.Fatalf("%q does not contain the symbolic name", msg)
	}
}
