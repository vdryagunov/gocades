package gocades

import (
	"encoding/base64"
	"testing"
)

func TestAttributesAddClearRemove(t *testing.T) {
	var a Attributes
	attr := Attribute{}
	attr.SetName(AttrDocumentName)
	attr.SetValueEncoding(EncodingBinary)
	if err := attr.SetValue("smoke-doc"); err != nil {
		t.Fatal(err)
	}
	a.Add(attr)
	if a.Count() != 1 {
		t.Fatalf("count = %d", a.Count())
	}
	got, err := a.Item(0)
	if err != nil {
		t.Fatal(err)
	}
	if got.OID != "1.3.6.1.4.1.311.88.2.1" {
		t.Fatalf("oid = %q", got.OID)
	}
	// CAPICOM encodes documentName as ASN.1 BMPString.
	if got.Value()[0] != 0x1e {
		t.Fatalf("value tag = %x, want BMPString", got.Value())
	}

	attr2 := Attribute{OID: "1.2.3.4"}
	attr2.SetValueEncoding(EncodingBase64)
	if err := attr2.SetValue(base64.StdEncoding.EncodeToString([]byte("xyz"))); err != nil {
		t.Fatal(err)
	}
	a.Add(attr2)
	if a.Count() != 2 {
		t.Fatalf("count = %d", a.Count())
	}
	if err := a.Remove(0); err != nil {
		t.Fatal(err)
	}
	if a.Count() != 1 {
		t.Fatalf("count after remove = %d", a.Count())
	}
	got, _ = a.Item(0)
	if got.OID != "1.2.3.4" || string(got.Value()) != "xyz" {
		t.Fatalf("remaining = %+v", got)
	}
	a.Clear()
	if a.Count() != 0 {
		t.Fatalf("clear left %d", a.Count())
	}
}

func TestAttributeSigningTime(t *testing.T) {
	attr := Attribute{}
	attr.SetName(AttrSigningTime)
	if err := attr.SetValue("20240102150405Z"); err != nil {
		t.Fatal(err)
	}
	v := attr.Value()
	if len(v) < 2 || v[0] != 0x17 {
		t.Fatalf("want UTCTime, got %x", v)
	}
}
