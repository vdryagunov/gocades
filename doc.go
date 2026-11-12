// Package gocades provides a cgo binding to the CryptoPro CAdES C API.
//
// Supported platforms: Linux and macOS, with CGO_ENABLED=1.
//
// Linux expects the packages under /opt/cprocsp (include/ and lib/).
// macOS expects CryptoPro ECP installed as /Applications/CryptoPro_ECP.app: the
// headers live in Contents/Resources/include and the dylibs in
// Contents/MacOS/lib.
package gocades
