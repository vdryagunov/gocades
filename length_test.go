// The race detector enables checkptr, which rightly rejects the fake 4 GiB
// slice below.

//go:build !race

package gocades

import (
	"errors"
	"testing"
	"unsafe"
)

// TestOversizedInputRejected checks that a length CryptoAPI cannot take as a
// DWORD is refused instead of truncated. The slice only claims 4 GiB: the
// C side must reject it before reading, so no such buffer is allocated.
func TestOversizedInputRejected(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) < 8 {
		t.Skip("needs a 64-bit platform")
	}
	var b [1]byte
	huge := unsafe.Slice(&b[0], 1<<32)

	_, err := digest(HashAlgGOST3411_2012_256, huge)
	var he *Error
	if !errors.As(err, &he) || he.Code != hrEInvalidArg {
		t.Fatalf("digest(4 GiB) = %v, want E_INVALIDARG", err)
	}
}
