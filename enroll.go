//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

// EnrollCspInformation mirrors X509Enrollment.CCspInformation for the
// container-enumeration subset used by pycades.
type EnrollCspInformation struct {
	name     string
	provType uint32
}

// NewEnrollCspInformation returns a CSP information object for the given
// provider name and type.
func NewEnrollCspInformation(name string, provType uint32) *EnrollCspInformation {
	return &EnrollCspInformation{name: name, provType: provType}
}

// NewEnrollCspInformationFromName resolves the provider type by name, like
// CCspInformation.InitializeFromName.
func NewEnrollCspInformationFromName(name string) (*EnrollCspInformation, error) {
	if name == "" {
		return nil, &Error{Op: "EnrollCspInformation.InitializeFromName", Code: hrEInvalidArg}
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var typ C.uint32_t
	if err := hrErr("EnrollCspInformation.InitializeFromName",
		C.cp_enroll_resolve_prov(cname, &typ)); err != nil {
		return nil, err
	}
	return &EnrollCspInformation{name: name, provType: uint32(typ)}, nil
}

// Name returns the CSP name.
func (c *EnrollCspInformation) Name() string {
	if c == nil {
		return ""
	}
	return c.name
}

// Type returns the CryptoAPI provider type.
func (c *EnrollCspInformation) Type() uint32 {
	if c == nil {
		return 0
	}
	return c.provType
}

// EnumContainers lists key containers of the CSP, like
// CCspInformation.EnumContainers.
func (c *EnrollCspInformation) EnumContainers() (EnrollContainers, error) {
	if c == nil {
		return EnrollContainers{}, &Error{Op: "EnrollCspInformation.EnumContainers", Code: hrEInvalidArg}
	}
	var cname *C.char
	if c.name != "" {
		cname = C.CString(c.name)
		defer C.free(unsafe.Pointer(cname))
	}
	var list C.cp_enroll_container_list
	rc := C.cp_enroll_enum_containers(cname, C.uint32_t(c.provType), &list)
	if err := hrErr("EnrollCspInformation.EnumContainers", rc); err != nil {
		return EnrollContainers{}, err
	}
	defer C.cp_enroll_container_list_free(list)

	out := EnrollContainers{items: make([]*EnrollContainer, 0, list.len)}
	if list.len == 0 || list.items == nil {
		return out, nil
	}
	slice := unsafe.Slice(list.items, list.len)
	for i := range slice {
		out.items = append(out.items, containerFromC(&slice[i], c.name, c.provType))
	}
	return out, nil
}

// ContainerByName opens one container by FQCN or short name, like
// CCspInformation.ContainerByName.
func (c *EnrollCspInformation) ContainerByName(name string) (*EnrollContainer, error) {
	if c == nil || name == "" {
		return nil, &Error{Op: "EnrollCspInformation.ContainerByName", Code: hrEInvalidArg}
	}
	var cname *C.char
	if c.name != "" {
		cname = C.CString(c.name)
		defer C.free(unsafe.Pointer(cname))
	}
	ccont := C.CString(name)
	defer C.free(unsafe.Pointer(ccont))
	var info C.cp_enroll_container
	rc := C.cp_enroll_container_info(ccont, cname, C.uint32_t(c.provType), 1, &info)
	if err := hrErr("EnrollCspInformation.ContainerByName", rc); err != nil {
		return nil, err
	}
	defer freeEnrollContainerC(&info)
	return containerFromC(&info, c.name, c.provType), nil
}

func freeEnrollContainerC(info *C.cp_enroll_container) {
	C.free(unsafe.Pointer(info.fqcn))
	C.free(unsafe.Pointer(info.unique_name))
	C.free(unsafe.Pointer(info.name))
	C.free(unsafe.Pointer(info.media))
	C.free(unsafe.Pointer(info.reader))
	info.fqcn = nil
	info.unique_name = nil
	info.name = nil
	info.media = nil
	info.reader = nil
}

func containerFromC(info *C.cp_enroll_container, provName string, provType uint32) *EnrollContainer {
	return &EnrollContainer{
		fqcn:     C.GoString(info.fqcn),
		unique:   C.GoString(info.unique_name),
		name:     C.GoString(info.name),
		media:    C.GoString(info.media),
		reader:   C.GoString(info.reader),
		provName: provName,
		provType: provType,
		silent:   true,
	}
}

// EnrollContainers mirrors CPPEnrollContainers.
type EnrollContainers struct {
	items []*EnrollContainer
}

// Count returns the number of containers.
func (c EnrollContainers) Count() int { return len(c.items) }

// Item returns the container at index i (0-based), like ItemByIndex.
func (c EnrollContainers) Item(i int) (*EnrollContainer, error) {
	if i < 0 || i >= len(c.items) {
		return nil, fmt.Errorf("gocades: container index %d out of range [0,%d)", i, len(c.items))
	}
	return c.items[i], nil
}

// ItemByIndex is an alias of Item for pycades naming.
func (c EnrollContainers) ItemByIndex(i int) (*EnrollContainer, error) {
	return c.Item(i)
}

// All returns every container.
func (c EnrollContainers) All() []*EnrollContainer { return c.items }

// EnrollContainer mirrors CPPEnrollContainer.
type EnrollContainer struct {
	fqcn, unique, name, media, reader string
	provName                          string
	provType                          uint32
	silent                            bool
}

// UniqueName returns PP_UNIQUE_CONTAINER.
func (c *EnrollContainer) UniqueName() string {
	if c == nil {
		return ""
	}
	return c.unique
}

// FQCN returns the fully qualified container name.
func (c *EnrollContainer) FQCN() string {
	if c == nil {
		return ""
	}
	return c.fqcn
}

// Name returns the short container name.
func (c *EnrollContainer) Name() string {
	if c == nil {
		return ""
	}
	return c.name
}

// Media returns the media component of the FQCN (same as Reader for HDIMAGE).
func (c *EnrollContainer) Media() string {
	if c == nil {
		return ""
	}
	return c.media
}

// Reader returns the reader component of the FQCN.
func (c *EnrollContainer) Reader() string {
	if c == nil {
		return ""
	}
	return c.reader
}

// SetSilent selects CRYPT_SILENT for Keys and Delete, like propset_Silent.
func (c *EnrollContainer) SetSilent(v bool) {
	if c != nil {
		c.silent = v
	}
}

// Keys returns the AT_KEYEXCHANGE / AT_SIGNATURE keys of the container.
func (c *EnrollContainer) Keys() (EnrollContainerKeys, error) {
	if c == nil || c.fqcn == "" {
		return EnrollContainerKeys{}, &Error{Op: "EnrollContainer.Keys", Code: hrEInvalidArg}
	}
	ccont := C.CString(c.fqcn)
	defer C.free(unsafe.Pointer(ccont))
	var cname *C.char
	if c.provName != "" {
		cname = C.CString(c.provName)
		defer C.free(unsafe.Pointer(cname))
	}
	var silent C.int32_t
	if c.silent {
		silent = 1
	}
	var list C.cp_enroll_key_list
	rc := C.cp_enroll_container_keys(ccont, cname, C.uint32_t(c.provType), silent, &list)
	if err := hrErr("EnrollContainer.Keys", rc); err != nil {
		return EnrollContainerKeys{}, err
	}
	defer C.cp_enroll_key_list_free(list)

	out := EnrollContainerKeys{items: make([]*EnrollContainerKey, 0, list.len)}
	if list.len == 0 || list.items == nil {
		return out, nil
	}
	slice := unsafe.Slice(list.items, list.len)
	for i := range slice {
		out.items = append(out.items, keyFromC(&slice[i]))
	}
	return out, nil
}

// Delete removes the key container (CRYPT_DELETEKEYSET).
func (c *EnrollContainer) Delete() error {
	if c == nil || c.fqcn == "" {
		return &Error{Op: "EnrollContainer.Delete", Code: hrEInvalidArg}
	}
	ccont := C.CString(c.fqcn)
	defer C.free(unsafe.Pointer(ccont))
	var cname *C.char
	if c.provName != "" {
		cname = C.CString(c.provName)
		defer C.free(unsafe.Pointer(cname))
	}
	var silent C.int32_t
	if c.silent {
		silent = 1
	}
	return hrErr("EnrollContainer.Delete",
		C.cp_enroll_container_delete(ccont, cname, C.uint32_t(c.provType), silent))
}

func keyFromC(k *C.cp_enroll_key) *EnrollContainerKey {
	out := &EnrollContainerKey{
		exportable: k.is_exportable != 0,
		hasCert:    k.has_certificate != 0,
		keyType:    uint32(k._type),
		fp:         C.GoString(k.kp_fp),
		algid:      uint32(k.kp_algid),
	}
	if k.expiration != 0 {
		out.expiration = time.Unix(int64(k.expiration), 0).UTC()
	}
	if k.certificate != nil {
		out.cert = newCertificate(k.certificate)
		k.certificate = nil // ownership moved
	}
	if k.pubkey_oid != nil || k.pubkey_key.len > 0 {
		out.pub = &PublicKey{
			algorithm:         C.GoString(k.pubkey_oid),
			encodedKey:        bufToBytes(k.pubkey_key),
			encodedParameters: bufToBytes(k.pubkey_params),
			length:            int(k.pubkey_bits),
		}
		k.pubkey_key.data = nil
		k.pubkey_key.len = 0
		k.pubkey_params.data = nil
		k.pubkey_params.len = 0
	}
	runtime.SetFinalizer(out, (*EnrollContainerKey).Close)
	return out
}

// EnrollContainerKeys mirrors CPPEnrollContainerKeys.
type EnrollContainerKeys struct {
	items []*EnrollContainerKey
}

// Count returns the number of keys.
func (k EnrollContainerKeys) Count() int { return len(k.items) }

// Item returns the key at index i.
func (k EnrollContainerKeys) Item(i int) (*EnrollContainerKey, error) {
	if i < 0 || i >= len(k.items) {
		return nil, fmt.Errorf("gocades: key index %d out of range [0,%d)", i, len(k.items))
	}
	return k.items[i], nil
}

// ItemByIndex is an alias of Item for pycades naming.
func (k EnrollContainerKeys) ItemByIndex(i int) (*EnrollContainerKey, error) {
	return k.Item(i)
}

// All returns every key.
func (k EnrollContainerKeys) All() []*EnrollContainerKey { return k.items }

// Close releases certificates held by the keys.
func (k EnrollContainerKeys) Close() {
	for _, it := range k.items {
		it.Close()
	}
}

// KeySpec values for EnrollContainerKey.Type.
const (
	KeySpecExchange  uint32 = 1 // AT_KEYEXCHANGE
	KeySpecSignature uint32 = 2 // AT_SIGNATURE
)

// EnrollContainerKey mirrors CPPEnrollContainerKey.
type EnrollContainerKey struct {
	exportable bool
	hasCert    bool
	keyType    uint32
	expiration time.Time
	fp         string
	algid      uint32
	cert       *Certificate
	pub        *PublicKey
}

// Close releases the certificate owned by the key, if any.
func (k *EnrollContainerKey) Close() {
	if k == nil {
		return
	}
	if k.cert != nil {
		k.cert.Close()
		k.cert = nil
	}
	runtime.SetFinalizer(k, nil)
}

// IsExportable reports whether the key has CRYPT_EXPORT permission.
func (k *EnrollContainerKey) IsExportable() bool {
	return k != nil && k.exportable
}

// HasCertificate reports whether KP_CERTIFICATE is present.
func (k *EnrollContainerKey) HasCertificate() bool {
	return k != nil && k.hasCert
}

// Type returns AT_KEYEXCHANGE or AT_SIGNATURE.
func (k *EnrollContainerKey) Type() uint32 {
	if k == nil {
		return 0
	}
	return k.keyType
}

// ExpirationTime returns KP_NOTAFTER, or a zero time when unknown.
func (k *EnrollContainerKey) ExpirationTime() time.Time {
	if k == nil {
		return time.Time{}
	}
	return k.expiration
}

// Certificate returns the certificate stored in the container, or nil.
// The caller does not own it; use Close on the key (or Keys.Close) to free it.
func (k *EnrollContainerKey) Certificate() *Certificate {
	if k == nil {
		return nil
	}
	return k.cert
}

// PublicKey returns the public key of the container key.
func (k *EnrollContainerKey) PublicKey() *PublicKey {
	if k == nil {
		return nil
	}
	return k.pub
}

// KP_FP returns the key fingerprint string (KP_FP).
func (k *EnrollContainerKey) KP_FP() string {
	if k == nil {
		return ""
	}
	return k.fp
}

// KP_ALGID returns the key algorithm identifier.
func (k *EnrollContainerKey) KP_ALGID() uint32 {
	if k == nil {
		return 0
	}
	return k.algid
}
