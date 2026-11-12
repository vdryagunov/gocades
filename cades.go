//go:build (linux || darwin) && cgo

package gocades

/*
// Linux: both layers of the CryptoAPI emulation are in libcapi20; libcapi10 is
// also linked because the CAdES libraries depend on it.
#cgo linux CFLAGS: -std=c11 -DUNIX -DSIZEOF_VOID_P=8
#cgo linux CFLAGS: -I/opt/cprocsp/include
#cgo linux CFLAGS: -I/opt/cprocsp/include/cpcsp
#cgo linux CFLAGS: -I/opt/cprocsp/include/pki
#cgo linux CFLAGS: -I/opt/cprocsp/include/pki/atl
#cgo linux CFLAGS: -I/opt/cprocsp/include/pki/cplib
#cgo linux LDFLAGS: -L/opt/cprocsp/lib -L/opt/cprocsp/lib/amd64 -L/opt/cprocsp/lib/aarch64
#cgo linux LDFLAGS: -lxades -lcades -lcapi20 -lcapi10 -lrdrsup

// macOS: CryptoPro ECP keeps the CAdES/CSP headers inside the app bundle and
// the dylibs in Contents/MacOS/lib. The provider-level CryptoAPI (CryptAcquire-
// Context, CryptCreateHash, CryptSignHash, ...) is libcapi10 there; the
// message layer is libcapi20.
#cgo darwin CFLAGS: -std=c11 -DUNIX -DSIZEOF_VOID_P=8
#cgo darwin CFLAGS: -I/Applications/CryptoPro_ECP.app/Contents/Resources/include/pki
#cgo darwin CFLAGS: -I/Applications/CryptoPro_ECP.app/Contents/Resources/include/pki/cplib
#cgo darwin CFLAGS: -I/opt/cprocsp/include
#cgo darwin CFLAGS: -I/opt/cprocsp/include/cpcsp
#cgo darwin LDFLAGS: -L/opt/cprocsp/lib
#cgo darwin LDFLAGS: -L/Applications/CryptoPro_ECP.app/Contents/MacOS/lib
#cgo darwin LDFLAGS: -Wl,-rpath,/Applications/CryptoPro_ECP.app/Contents/MacOS/lib
#cgo darwin LDFLAGS: -lxades -lcades -lcapi20 -lcapi10 -lrdrsup

#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import "unsafe"

func hrErr(op string, code C.int32_t) error {
	if code == 0 {
		return nil
	}
	return &Error{Op: op, Code: int32(code)}
}

func bufToBytes(b C.cp_buf) []byte {
	defer C.cp_buf_free(b)
	if b.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(b.data), C.int(b.len))
}

func bytesPtr(p []byte) *C.uchar {
	if len(p) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&p[0]))
}

func boolToC(b bool) C.int32_t {
	if b {
		return 1
	}
	return 0
}
