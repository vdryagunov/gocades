package gocades

import (
	"encoding/base64"
	"testing"
)

func TestEncodedDataFormatAndDecode(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xff, 'A'}
	ed := NewEncodedData(raw)
	if got := ed.Value(); string(got) != string(raw) {
		t.Fatalf("Value = %v", got)
	}

	b64, err := ed.Format(EncodingBase64)
	if err != nil {
		t.Fatal(err)
	}
	if b64 != base64.StdEncoding.EncodeToString(raw) {
		t.Fatalf("Format(Base64) = %q", b64)
	}
	any, err := ed.Format(EncodingAny)
	if err != nil || any != b64 {
		t.Fatalf("Format(Any) = %q, %v", any, err)
	}
	bin, err := ed.Format(EncodingBinary)
	if err != nil || bin != string(raw) {
		t.Fatalf("Format(Binary) = %q, %v", bin, err)
	}
	if _, err := ed.Format(EncodingType(99)); err == nil {
		t.Fatal("unsupported Format: want error")
	}

	got, err := decodeEncodedData(b64, EncodingBase64)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("decode Base64 = %v, %v", got, err)
	}
	got, err = decodeEncodedData(string(raw), EncodingBinary)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("decode Binary = %v, %v", got, err)
	}
	got, err = decodeEncodedData(b64, EncodingAny)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("decode Any(base64) = %v, %v", got, err)
	}
	got, err = decodeEncodedData("not!!base64", EncodingAny)
	if err != nil || string(got) != "not!!base64" {
		t.Fatalf("decode Any(raw) = %v, %v", got, err)
	}
	if _, err := decodeEncodedData("@@@", EncodingBase64); err == nil {
		t.Fatal("bad base64: want error")
	}
	if _, err := decodeEncodedData("", EncodingType(99)); err == nil {
		t.Fatal("unsupported decode: want error")
	}

	ed.SetValue([]byte("x"))
	if string(ed.Value()) != "x" {
		t.Fatal("SetValue")
	}
}
