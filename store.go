//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// Store is an opened certificate store.
//
// Methods called on a store that is not open (NewStore without Open, or after
// Close) return ErrClosed.
type Store struct {
	h        unsafe.Pointer
	location StoreLocation
	name     string
}

// NewStore returns a closed store handle, like pycades.Store().
func NewStore() *Store { return &Store{} }

// handle returns the store handle, or ErrClosed.
//
// The caller must keep s alive (runtime.KeepAlive) until the C call that uses
// the handle returns.
func (s *Store) handle() (unsafe.Pointer, error) {
	if s == nil {
		return nil, errors.New("gocades: nil store")
	}
	if s.h == nil {
		return nil, ErrClosed
	}
	return s.h, nil
}

// optionalStoreHandle is handle for an optional store: nil means "no store".
// A store that was registered and then closed is an error, not "no store".
func optionalStoreHandle(s *Store) (unsafe.Pointer, error) {
	if s == nil {
		return nil, nil
	}
	return s.handle()
}

// Open opens a system store in place, like CadesStore.Open.
//
// location is StoreLocalMachine, StoreCurrentUser or StoreMemory; name is
// usually "My".
func (s *Store) Open(location StoreLocation, name string) error {
	if s.h != nil {
		return &Error{Op: "Store.Open", Code: hrEInvalidArg}
	}

	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	var h unsafe.Pointer
	if err := hrErr("Store.Open",
		C.cp_store_open(C.int32_t(location), cname, &h)); err != nil {
		return err
	}

	s.h = h
	s.location = location
	s.name = name
	runtime.SetFinalizer(s, (*Store).Close)
	return nil
}

// OpenStore opens a system certificate store.
//
// location is StoreLocalMachine or StoreCurrentUser; name is usually "My".
func OpenStore(location StoreLocation, name string) (*Store, error) {
	s := NewStore()
	if err := s.Open(location, name); err != nil {
		return nil, err
	}
	return s, nil
}

// Location returns the store location, "CurrentUser", "LocalMachine" or
// "Memory", like CadesStore.Location.
func (s *Store) Location() string {
	switch s.location {
	case StoreLocalMachine:
		return "LocalMachine"
	case StoreMemory:
		return "Memory"
	}
	return "CurrentUser"
}

// Name returns the store name, usually "My", like CadesStore.Name.
func (s *Store) Name() string { return s.name }

// Add imports a certificate into the store, like CadesStore.Add.
func (s *Store) Add(cert *Certificate) error {
	hc, err := cert.handle()
	if err != nil {
		return err
	}
	hs, err := s.handle()
	if err != nil {
		return err
	}
	rc := C.cp_store_add_cert(hs, hc)
	runtime.KeepAlive(s)
	runtime.KeepAlive(cert)
	return hrErr("Store.Add", rc)
}

// Remove deletes the store's copy of cert, like CadesStore.Remove. cert
// itself stays usable. A certificate that is not in the store yields
// CRYPT_E_NOT_FOUND.
func (s *Store) Remove(cert *Certificate) error {
	hc, err := cert.handle()
	if err != nil {
		return err
	}
	hs, err := s.handle()
	if err != nil {
		return err
	}
	rc := C.cp_store_remove_cert(hs, hc)
	runtime.KeepAlive(s)
	runtime.KeepAlive(cert)
	return hrErr("Store.Remove", rc)
}

// AddCRL imports a DER-encoded CRL into the store, like CadesStore.AddCRL.
func (s *Store) AddCRL(der []byte) error {
	if len(der) == 0 {
		return &Error{Op: "Store.AddCRL", Code: hrEInvalidArg}
	}
	hs, err := s.handle()
	if err != nil {
		return err
	}
	rc := C.cp_store_add_crl(hs, bytesPtr(der), C.size_t(len(der)))
	runtime.KeepAlive(s)
	return hrErr("Store.AddCRL", rc)
}

// PFXImportFlags are the PFXImportCertStore flags of Store.ImportPFX; they
// combine with |.
type PFXImportFlags uint32

const (
	// PFXExportable marks the imported keys exportable (CRYPT_EXPORTABLE).
	PFXExportable PFXImportFlags = 0x1
	// PFXUserProtected asks the CSP to protect the keys (CRYPT_USER_PROTECTED).
	PFXUserProtected PFXImportFlags = 0x2
	// PFXMachineKeyset puts the keys into machine containers
	// (CRYPT_MACHINE_KEYSET).
	PFXMachineKeyset PFXImportFlags = 0x20
	// PFXUserKeyset puts the keys into user containers (CRYPT_USER_KEYSET).
	PFXUserKeyset PFXImportFlags = 0x1000
	// PFXNoPersistKey keeps the keys out of persistent containers
	// (PKCS12_NO_PERSIST_KEY), if the CSP supports it.
	PFXNoPersistKey PFXImportFlags = 0x8000
)

// ImportPFX imports a DER-encoded PFX (PKCS #12) protected by password, like
// CadesStore.ImportPFX. The private keys go into key containers of the CSP.
//
// On a store that is not open (NewStore), the store becomes the in-memory
// store of the PFX, as in CAdESCOM; its Location is "Memory". On an open
// store, the certificates of the PFX are added to it with their key links,
// replacing existing copies. CAdESCOM drops them in that case, so the keys
// land in containers that no certificate refers to.
func (s *Store) ImportPFX(pfx []byte, password string, flags PFXImportFlags) error {
	if s == nil {
		return errors.New("gocades: nil store")
	}
	if len(pfx) == 0 {
		return &Error{Op: "Store.ImportPFX", Code: hrEInvalidArg}
	}

	// LPCWSTR: wchar_t is 32 bits on Linux and macOS.
	wpass := make([]C.wchar_t, 0, len(password)+1)
	for _, r := range password {
		wpass = append(wpass, C.wchar_t(r))
	}
	wpass = append(wpass, 0)
	defer clear(wpass)

	var out unsafe.Pointer
	rc := C.cp_store_import_pfx(s.h, bytesPtr(pfx), C.size_t(len(pfx)),
		&wpass[0], C.uint32_t(flags), &out)
	runtime.KeepAlive(s)
	if err := hrErr("Store.ImportPFX", rc); err != nil {
		return err
	}
	if s.h == nil {
		s.h = out
		s.location = StoreMemory
		s.name = ""
		runtime.SetFinalizer(s, (*Store).Close)
	}
	return nil
}

// Close closes the store.
//
// Certificates obtained from the store stay valid: each holds its own
// reference to the underlying context.
func (s *Store) Close() {
	if s != nil && s.h != nil {
		C.cp_store_close(s.h)
		s.h = nil
		runtime.SetFinalizer(s, nil)
	}
}

// FindBySHA1 finds a certificate by its 20-byte SHA-1 thumbprint.
func (s *Store) FindBySHA1(sha1 []byte) (*Certificate, error) {
	hs, err := s.handle()
	if err != nil {
		return nil, err
	}
	var h unsafe.Pointer
	rc := C.cp_store_find_cert_sha1(hs, bytesPtr(sha1), C.size_t(len(sha1)), &h)
	runtime.KeepAlive(s)
	if err := hrErr("Store.FindBySHA1", rc); err != nil {
		return nil, err
	}
	return newCertificate(h), nil
}

// FindBySubject finds a certificate by a substring of the subject name.
func (s *Store) FindBySubject(subject string) (*Certificate, error) {
	hs, err := s.handle()
	if err != nil {
		return nil, err
	}
	csubj := C.CString(subject)
	defer C.free(unsafe.Pointer(csubj))

	var h unsafe.Pointer
	rc := C.cp_store_find_cert_subject(hs, csubj, &h)
	runtime.KeepAlive(s)
	if err := hrErr("Store.FindBySubject", rc); err != nil {
		return nil, err
	}
	return newCertificate(h), nil
}

// Certificates enumerates all certificates in the store.
func (s *Store) Certificates() ([]*Certificate, error) {
	hs, err := s.handle()
	if err != nil {
		return nil, err
	}
	var l C.cp_cert_list
	rc := C.cp_store_enum_certs(hs, &l)
	runtime.KeepAlive(s)
	if err := hrErr("Store.Certificates", rc); err != nil {
		return nil, err
	}
	defer C.cp_cert_list_free(l)
	if l.len == 0 {
		return nil, nil
	}

	items := unsafe.Slice(l.items, int(l.len))
	out := make([]*Certificate, 0, int(l.len))
	for _, p := range items {
		out = append(out, newCertificate(p))
	}
	return out, nil
}
