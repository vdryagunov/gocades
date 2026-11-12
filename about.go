//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Version is a CryptoPro CSP version.
type Version struct {
	Major int
	Minor int
	Build int
}

// String renders the version as "major.minor.build".
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
}

// About mirrors CadesAbout.
//
// PluginVersion is not modelled: it describes the browser plug-in, which does
// not exist on Linux.
type About struct{}

// CryptoAPI provider types for CSPName and CSPVersionOf.
const (
	ProvRSAFull uint32 = 1
	// ProvGOST2001DH is the default of CAdESCOM About.CSPName/CSPVersion.
	ProvGOST2001DH   uint32 = 75
	ProvGOST2012_256 uint32 = 80
	ProvGOST2012_512 uint32 = 81
)

// CSPVersion returns the version of the default provider of type
// ProvGOST2001DH, like CadesAbout.CSPVersion() without arguments.
//
// Build is the CSP build from PP_VERSION_EX (SKZI_Build), the number csptest
// prints as "v5.0.<build>"; it is not the product release ("Ver:"). Build is
// 0 when the provider does not report it.
func (a About) CSPVersion() (Version, error) {
	return a.CSPVersionOf("", ProvGOST2001DH)
}

// CSPVersionOf returns the version of provider name ("" = the default one)
// of type provType, like CadesAbout.CSPVersion(name, type).
func (About) CSPVersionOf(name string, provType uint32) (Version, error) {
	var cname *C.char
	if name != "" {
		cname = C.CString(name)
		defer C.free(unsafe.Pointer(cname))
	}
	var v C.cp_csp_version
	if err := hrErr("About.CSPVersion",
		C.cp_csp_version_info(cname, C.uint32_t(provType), &v)); err != nil {
		return Version{}, err
	}
	return Version{
		Major: int(v.major),
		Minor: int(v.minor),
		Build: int(v.build),
	}, nil
}

// CSPName returns the name of the default provider of type provType, like
// CadesAbout.CSPName (pycades defaults to ProvGOST2001DH).
func (About) CSPName(provType uint32) (string, error) {
	var b C.cp_buf
	if err := hrErr("About.CSPName", C.cp_csp_name(C.uint32_t(provType), &b)); err != nil {
		return "", err
	}
	return string(bufToBytes(b)), nil
}
