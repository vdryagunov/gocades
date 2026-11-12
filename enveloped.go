//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

// Recipients mirrors CadesRecipients: the certificates to encrypt for.
type Recipients struct {
	items []*Certificate
}

// NewRecipients returns an empty recipient list.
func NewRecipients() *Recipients { return &Recipients{} }

// Add appends a recipient certificate, like CadesRecipients.Add.
func (r *Recipients) Add(c *Certificate) error {
	if c == nil {
		return ErrNilCertificate
	}
	r.items = append(r.items, c)
	return nil
}

// Count returns the number of recipients.
func (r *Recipients) Count() int { return len(r.items) }

// Item returns the recipient at index i.
func (r *Recipients) Item(i int) (*Certificate, error) {
	if i < 0 || i >= len(r.items) {
		return nil, fmt.Errorf("gocades: recipient index %d out of range [0,%d)", i, len(r.items))
	}
	return r.items[i], nil
}

// Remove drops the recipient at index i.
func (r *Recipients) Remove(i int) error {
	if i < 0 || i >= len(r.items) {
		return fmt.Errorf("gocades: recipient index %d out of range [0,%d)", i, len(r.items))
	}
	r.items = append(r.items[:i], r.items[i+1:]...)
	return nil
}

// Clear removes all recipients.
func (r *Recipients) Clear() { r.items = nil }

// All returns the recipient list.
func (r *Recipients) All() []*Certificate { return r.items }

// EnvelopedData mirrors CadesEnvelopedData: CMS enveloped (encrypted) content.
type EnvelopedData struct {
	content    []byte
	encoding   EncodingType
	algorithm  Algorithm
	recipients Recipients
	store      *Store
}

// NewEnvelopedData returns an empty object defaulting to GOST 28147-89.
func NewEnvelopedData() *EnvelopedData {
	return &EnvelopedData{
		encoding:  EncodingBinary,
		algorithm: Algorithm{Name: EncryptionGOST28147, KeyLength: KeyLengthMaximum},
	}
}

// SetContent sets the content to encrypt or that was decrypted.
func (e *EnvelopedData) SetContent(content []byte) { e.content = content }

// Content returns the current content.
func (e *EnvelopedData) Content() []byte { return e.content }

// SetContentEncoding records the content presentation; it does not affect the
// encryption.
func (e *EnvelopedData) SetContentEncoding(t EncodingType) { e.encoding = t }

// ContentEncoding returns the configured presentation.
func (e *EnvelopedData) ContentEncoding() EncodingType { return e.encoding }

// SetAlgorithm selects the content encryption algorithm.
func (e *EnvelopedData) SetAlgorithm(a Algorithm) { e.algorithm = a }

// Algorithm returns the content encryption algorithm.
func (e *EnvelopedData) Algorithm() Algorithm { return e.algorithm }

// Recipients returns the recipient list.
func (e *EnvelopedData) Recipients() *Recipients { return &e.recipients }

// SetStore sets the store used to find the recipient key when decrypting.
func (e *EnvelopedData) SetStore(s *Store) { e.store = s }

// Encrypt encrypts Content for the configured recipients, like
// CadesEnvelopedData.Encrypt.
func (e *EnvelopedData) Encrypt() ([]byte, error) {
	n := len(e.recipients.items)
	if n == 0 {
		return nil, errors.New("gocades: no recipients: add at least one certificate")
	}

	// Build the recipient array in C memory: cgo must not see a Go slice of
	// pointers here.
	ptrSize := C.size_t(unsafe.Sizeof(uintptr(0)))
	arr := C.malloc(C.size_t(n) * ptrSize)
	if arr == nil {
		return nil, errors.New("gocades: out of memory")
	}
	defer C.free(arr)

	slots := unsafe.Slice((*unsafe.Pointer)(arr), n)
	for i, c := range e.recipients.items {
		h, err := c.handle()
		if err != nil {
			return nil, err
		}
		slots[i] = h
	}

	var out C.cp_buf
	rc := C.cp_envelope_encrypt((*unsafe.Pointer)(arr), C.size_t(n),
		C.int32_t(e.algorithm.Name),
		bytesPtr(e.content), C.size_t(len(e.content)), &out)
	runtime.KeepAlive(e.recipients.items)

	if rc != 0 {
		return nil, hrErr("EnvelopedData.Encrypt", rc)
	}
	return bufToBytes(out), nil
}

// Decrypt decrypts ciphertext, like CadesEnvelopedData.Decrypt.
//
// A certificate store holding the recipient key is required; set it with
// SetStore.
func (e *EnvelopedData) Decrypt(ciphertext []byte) ([]byte, error) {
	if e.store == nil {
		return nil, errors.New("gocades: EnvelopedData.Decrypt requires a certificate store (SetStore)")
	}
	hs, err := e.store.handle()
	if err != nil {
		return nil, err
	}

	var out C.cp_buf
	rc := C.cp_envelope_decrypt(hs,
		bytesPtr(ciphertext), C.size_t(len(ciphertext)), &out)
	runtime.KeepAlive(e.store)

	if rc != 0 {
		return nil, hrErr("EnvelopedData.Decrypt", rc)
	}
	return bufToBytes(out), nil
}

// StreamEncrypt encrypts the content of r and writes the CMS to w.
//
// The CSP only offers one-shot encryption, so r is consumed into memory first.
func (e *EnvelopedData) StreamEncrypt(r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	e.content = data

	encrypted, err := e.Encrypt()
	if err != nil {
		return err
	}

	_, err = w.Write(encrypted)
	return err
}

// StreamDecrypt decrypts the CMS read from r and writes the content to w.
func (e *EnvelopedData) StreamDecrypt(r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	decrypted, err := e.Decrypt(data)
	if err != nil {
		return err
	}

	_, err = w.Write(decrypted)
	return err
}
