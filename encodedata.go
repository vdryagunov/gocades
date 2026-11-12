package gocades

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// EncodingType mirrors CAPICOM_ENCODING_TYPE.
type EncodingType int32

const (
	// EncodingAny keeps whatever representation is already there.
	EncodingAny EncodingType = -1
	// EncodingBase64 renders the value as base64.
	EncodingBase64 EncodingType = 0
	// EncodingBinary renders the value as a raw byte string.
	EncodingBinary EncodingType = 1
)

// EncodedData mirrors CadesEncodedData: a byte value and its presentation.
type EncodedData struct {
	value []byte
}

// NewEncodedData wraps raw bytes.
func NewEncodedData(v []byte) *EncodedData { return &EncodedData{value: v} }

// SetValue replaces the underlying bytes.
func (e *EncodedData) SetValue(v []byte) { e.value = v }

// Value returns the underlying bytes.
func (e *EncodedData) Value() []byte { return e.value }

// Format renders the value as base64 or as a raw byte string.
func (e *EncodedData) Format(t EncodingType) (string, error) {
	switch t {
	case EncodingAny, EncodingBase64:
		return base64.StdEncoding.EncodeToString(e.value), nil
	case EncodingBinary:
		return string(e.value), nil
	}
	return "", errors.New("gocades: unsupported encoding type")
}

// decodeEncodedData parses a value produced by Format.
func decodeEncodedData(encoded string, t EncodingType) ([]byte, error) {
	switch t {
	case EncodingAny:
		if b, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			return b, nil
		}
		return []byte(encoded), nil
	case EncodingBase64:
		b, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("gocades: invalid base64: %w", err)
		}
		return b, nil
	case EncodingBinary:
		return []byte(encoded), nil
	}
	return nil, errors.New("gocades: unsupported encoding type")
}
