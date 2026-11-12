package pdfsign

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

/* ------------------------------------------------------------------ */
/* fixture builders                                                    */
/* ------------------------------------------------------------------ */

// buildPDF assembles a classic cross-reference PDF from object bodies; object
// N occupies index N-1.
func buildPDF(t *testing.T, objects []string) []byte {
	t.Helper()
	return buildPDFWithTrailer(t, objects, "")
}

func buildPDFWithTrailer(t *testing.T, objects []string, extraTrailer string) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")

	offsets := make([]int, len(objects)+1)
	for i, body := range objects {
		offsets[i+1] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}

	xrefOff := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R%s >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, extraTrailer, xrefOff)

	return buf.Bytes()
}

func simplePDF(t *testing.T) []byte {
	t.Helper()
	return buildPDF(t, []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> /Contents 4 0 R >>",
		"<< /Length 4 >>\nstream\nq Q\nendstream",
	})
}

func acroFormPDF(t *testing.T) []byte {
	t.Helper()
	return buildPDF(t, []string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> /Contents 4 0 R >>",
		"<< /Length 4 >>\nstream\nq Q\nendstream",
		"<< /Fields [6 0 R] /DA (/Helv 0 Tf 0 g) >>",
		"<< /Type /Annot /Subtype /Widget /FT /Tx /T (Text1) /Rect [0 0 100 20] >>",
	})
}

// xrefStreamPDF builds a PDF 1.7 file whose catalog, page tree and page live in
// a compressed object stream, described by a compressed xref stream.
func xrefStreamPDF(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")

	offsets := map[int]int{}
	writeObj := func(num int, body []byte) {
		offsets[num] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", num)
		buf.Write(body)
		buf.WriteString("\nendobj\n")
	}

	content := []byte("q Q\n")
	writeObj(4, fmt.Appendf(nil,
		"<< /Length %d >>\nstream\n%s\nendstream", len(content), content))

	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << >> /Contents 4 0 R >>",
	}
	var hdr, payload bytes.Buffer
	for i, o := range objs {
		fmt.Fprintf(&hdr, "%d %d ", i+1, payload.Len())
		payload.WriteString(o)
		payload.WriteString(" ")
	}
	joined := append(append([]byte{}, hdr.Bytes()...), payload.Bytes()...)
	zObjs := deflate(t, joined)
	writeObj(5, fmt.Appendf(nil,
		"<< /Type /ObjStm /N %d /First %d /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream",
		len(objs), hdr.Len(), len(zObjs), zObjs))

	// The xref stream describes objects 0..6: 1..3 live in object stream 5,
	// 4 and 5 are plain objects, 6 is the xref stream itself.
	xrefOff := buf.Len()

	type ent [3]uint64
	entries := make([]ent, 7)
	entries[0] = ent{0, 0, 0}
	for i := 1; i <= 3; i++ {
		entries[i] = ent{2, 5, uint64(i - 1)}
	}
	entries[4] = ent{1, uint64(offsets[4]), 0}
	entries[5] = ent{1, uint64(offsets[5]), 0}
	entries[6] = ent{1, uint64(xrefOff), 0}

	var raw bytes.Buffer
	for _, e := range entries {
		raw.WriteByte(byte(e[0]))
		raw.Write([]byte{byte(e[1] >> 24), byte(e[1] >> 16), byte(e[1] >> 8), byte(e[1])})
		raw.Write([]byte{byte(e[2] >> 8), byte(e[2])})
	}
	zXref := deflate(t, raw.Bytes())

	writeObj(6, fmt.Appendf(nil,
		"<< /Type /XRef /Size 7 /W [1 4 2] /Root 1 0 R /Length %d /Filter /FlateDecode >>\nstream\n%s\nendstream",
		len(zXref), zXref))

	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefOff)
	return buf.Bytes()
}

func deflate(t *testing.T, data []byte) []byte {
	t.Helper()

	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("deflate: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("deflate: %v", err)
	}
	return z.Bytes()
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

// findSigField reopens pdf and returns the reader, the last signature field
// reference, the field dictionary and the signature dictionary.
func findSigField(t *testing.T, pdf []byte) (*pdfFile, Ref, Dict, Dict) {
	t.Helper()

	f, err := newPDFFile(pdf)
	if err != nil {
		t.Fatalf("reopen document: %v", err)
	}

	rootRef, ok := f.trailer["Root"].(Ref)
	if !ok {
		t.Fatal("trailer has no /Root reference")
	}
	catalog, err := f.rootCatalog(rootRef)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	acro, err := f.resolveDict(catalog["AcroForm"])
	if err != nil {
		t.Fatalf("/AcroForm: %v", err)
	}
	if acro == nil {
		t.Fatal("no /AcroForm")
	}
	fields, err := f.resolveArray(acro["Fields"])
	if err != nil {
		t.Fatalf("/Fields: %v", err)
	}
	if len(fields) == 0 {
		t.Fatal("AcroForm has no fields")
	}

	fldRef, ok := fields[len(fields)-1].(Ref)
	if !ok {
		t.Fatalf("last field is %T, want a reference", fields[len(fields)-1])
	}
	fldObj, err := f.resolve(fldRef.Num)
	if err != nil {
		t.Fatalf("resolve field: %v", err)
	}
	fld, ok := fldObj.(Dict)
	if !ok {
		t.Fatalf("field is %T, want a dictionary", fldObj)
	}

	vRef, ok := fld["V"].(Ref)
	if !ok {
		t.Fatal("signature field has no /V reference")
	}
	sigObj, err := f.resolve(vRef.Num)
	if err != nil {
		t.Fatalf("resolve signature: %v", err)
	}
	sig, ok := sigObj.(Dict)
	if !ok {
		t.Fatalf("signature is %T, want a dictionary", sigObj)
	}

	return f, fldRef, fld, sig
}

func intArray(t *testing.T, o Object) []int64 {
	t.Helper()

	arr, ok := o.(Array)
	if !ok {
		t.Fatalf("expected an array, got %T", o)
	}
	out := make([]int64, len(arr))
	for i, e := range arr {
		n, ok := toInt(e)
		if !ok {
			t.Fatalf("array element %d is %T, want an integer", i, e)
		}
		out[i] = n
	}
	return out
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

func TestPrepareAssembleClassic(t *testing.T) {
	pdf := simplePDF(t)

	prep, err := Prepare(pdf, Options{
		Hash:        HashSHA256,
		SigningTime: time.Unix(1700000000, 0),
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if !bytes.HasPrefix(prep.PDF, pdf) {
		t.Fatal("the prepared document does not start with the original bytes")
	}
	if prep.FieldName != "Signature1" {
		t.Fatalf("field name = %q, want Signature1", prep.FieldName)
	}
	if !bytes.Contains(prep.PDF[len(pdf):], []byte("\nxref\n")) {
		t.Fatal("the update over a classic file has no classic xref table")
	}

	br := prep.ByteRange
	if br[0] != 0 {
		t.Fatalf("/ByteRange[0] = %d, want 0", br[0])
	}
	if got := br[2] - br[1]; got != 2+2*DefaultPlaceholderSize {
		t.Fatalf("gap length = %d, want %d", got, 2+2*DefaultPlaceholderSize)
	}
	if int64(len(prep.PDF)) != br[2]+br[3] {
		t.Fatalf("length %d != %d + %d (byte range does not cover the document)",
			len(prep.PDF), br[2], br[3])
	}
	if prep.PDF[br[1]] != '<' || prep.PDF[br[2]-1] != '>' {
		t.Fatal("the /ByteRange gap is not a hex string")
	}

	sum := sha256.Sum256(prep.SignedContent())
	if !bytes.Equal(sum[:], prep.Digest) {
		t.Fatal("Prepared.Digest does not match SignedContent()")
	}

	cms := bytes.Repeat([]byte{0x30, 0x82, 0x12, 0x34}, 1500) // 6000 bytes
	signed, err := prep.Assemble(cms)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(signed) != len(prep.PDF) {
		t.Fatalf("signed length %d != prepared length %d", len(signed), len(prep.PDF))
	}
	if !bytes.Equal(signed[:br[1]], prep.PDF[:br[1]]) {
		t.Fatal("bytes before the placeholder changed")
	}
	if !bytes.Equal(signed[br[2]:], prep.PDF[br[2]:]) {
		t.Fatal("bytes after the placeholder changed")
	}

	h := sha256.New()
	h.Write(signed[:br[1]])
	h.Write(signed[br[2]:])
	if !bytes.Equal(h.Sum(nil), prep.Digest) {
		t.Fatal("assembling changed the signed bytes")
	}

	if !bytes.Contains(signed, []byte(hex.EncodeToString(cms))) {
		t.Fatal("the CMS was not hex-encoded into /Contents")
	}

	f, fldRef, fld, sigDict := findSigField(t, signed)

	if got := toName(fld["FT"]); got != "Sig" {
		t.Fatalf("/FT = %q, want Sig", got)
	}
	if got := toName(sigDict["SubFilter"]); got != "ETSI.CAdES.detached" {
		t.Fatalf("/SubFilter = %q, want ETSI.CAdES.detached", got)
	}

	gotBR := intArray(t, sigDict["ByteRange"])
	want := []int64{0, br[1], br[2], br[3]}
	if !slices.Equal(gotBR, want) {
		t.Fatalf("/ByteRange = %v, want %v", gotBR, want)
	}

	contents, ok := sigDict["Contents"].(HexString)
	if !ok {
		t.Fatalf("/Contents is %T, want a hex string", sigDict["Contents"])
	}
	if len(contents) != DefaultPlaceholderSize {
		t.Fatalf("/Contents holds %d bytes, want %d", len(contents), DefaultPlaceholderSize)
	}
	if !bytes.HasPrefix(contents, cms) {
		t.Fatal("/Contents does not start with the CMS")
	}
	for i, b := range contents[len(cms):] {
		if b != 0 {
			t.Fatalf("/Contents padding byte %d = %#x, want 0", len(cms)+i, b)
		}
	}

	// The widget must be attached to the last page.
	rootRef := f.trailer["Root"].(Ref)
	catalog, err := f.rootCatalog(rootRef)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	_, pageDict, err := f.selectPage(catalog, 0)
	if err != nil {
		t.Fatalf("last page: %v", err)
	}
	annots, err := f.resolveArray(pageDict["Annots"])
	if err != nil {
		t.Fatalf("/Annots: %v", err)
	}
	attached := false
	for _, a := range annots {
		if r, ok := a.(Ref); ok && r.Num == fldRef.Num {
			attached = true
		}
	}
	if !attached {
		t.Fatalf("widget %d is not in the page /Annots", fldRef.Num)
	}
}

func TestPrepareSecondSignature(t *testing.T) {
	first, err := Prepare(simplePDF(t), Options{Hash: HashSHA256, Reason: "first"})
	if err != nil {
		t.Fatalf("Prepare #1: %v", err)
	}
	signed1, err := first.Assemble(bytes.Repeat([]byte{0x11}, 300))
	if err != nil {
		t.Fatalf("Assemble #1: %v", err)
	}

	second, err := Prepare(signed1, Options{
		Hash:       HashSHA256,
		Reason:     "Согласовано (финал)",
		Location:   "Москва",
		SignerName: "Володя Яковлев",
	})
	if err != nil {
		t.Fatalf("Prepare #2: %v", err)
	}
	if second.FieldName != "Signature2" {
		t.Fatalf("field name = %q, want Signature2", second.FieldName)
	}
	// An incremental update must leave the signed first revision, including
	// its /ByteRange, byte for byte intact.
	if !bytes.HasPrefix(second.PDF, signed1) {
		t.Fatal("preparing the second signature changed the first revision")
	}

	signed2, err := second.Assemble(bytes.Repeat([]byte{0x22}, 300))
	if err != nil {
		t.Fatalf("Assemble #2: %v", err)
	}

	_, _, _, sigDict := findSigField(t, signed2)
	br := second.ByteRange
	if got := intArray(t, sigDict["ByteRange"]); !slices.Equal(got, []int64{0, br[1], br[2], br[3]}) {
		t.Fatalf("second /ByteRange = %v, want %v", got, br)
	}

	reason, ok := sigDict["Reason"].(String)
	if !ok {
		t.Fatalf("/Reason is %T, want a string", sigDict["Reason"])
	}
	if !bytes.HasPrefix(reason, []byte{0xFE, 0xFF}) {
		t.Fatalf("/Reason = % x, want UTF-16BE with a byte order mark", reason)
	}
	for key, want := range map[string]string{
		"Reason":   "Согласовано (финал)",
		"Location": "Москва",
		"Name":     "Володя Яковлев",
	} {
		s, _ := sigDict[key].(String)
		if got := decodeTextString(s); got != want {
			t.Errorf("/%s = %q, want %q", key, got, want)
		}
	}
}

func TestTextString(t *testing.T) {
	for _, s := range []string{"plain (ascii)\\", "Подпись", "a\x01b", "emoji 🙂"} {
		var p parser
		p.buf = []byte("(" + escapeTextString(s) + ")")
		obj, err := p.parseObject()
		if err != nil {
			t.Fatalf("%q: parse: %v", s, err)
		}
		raw, ok := obj.(String)
		if !ok {
			t.Fatalf("%q: parsed %T, want a string", s, obj)
		}
		if got := decodeTextString(raw); got != s {
			t.Errorf("round trip: got %q, want %q", got, s)
		}
		if isPDFDocASCII(s) {
			if !bytes.Equal(raw, []byte(s)) {
				t.Errorf("%q: ASCII text was re-encoded as % x", s, raw)
			}
		} else if !bytes.HasPrefix(raw, []byte{0xFE, 0xFF}) {
			t.Errorf("%q: got % x, want UTF-16BE with a byte order mark", s, raw)
		}
	}
}

func TestPrepareExistingAcroForm(t *testing.T) {
	prep, err := Prepare(acroFormPDF(t), Options{Hash: HashSHA256})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prep.FieldName != "Signature1" {
		t.Fatalf("field name = %q, want Signature1", prep.FieldName)
	}

	f, err := newPDFFile(prep.PDF)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	rootRef := f.trailer["Root"].(Ref)
	catalog, err := f.rootCatalog(rootRef)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}

	acroRef, ok := catalog["AcroForm"].(Ref)
	if !ok {
		t.Fatalf("/AcroForm = %T, want a reference (it must stay indirect)", catalog["AcroForm"])
	}
	acro, err := f.resolveDict(acroRef)
	if err != nil {
		t.Fatalf("/AcroForm: %v", err)
	}

	if got, _ := toInt(acro["SigFlags"]); got != 3 {
		t.Fatalf("/SigFlags = %d, want 3", got)
	}

	fields, err := f.resolveArray(acro["Fields"])
	if err != nil {
		t.Fatalf("/Fields: %v", err)
	}
	if len(fields) != 2 {
		t.Fatalf("/Fields has %d entries, want 2 (the text field plus the signature)", len(fields))
	}
	first, _ := fields[0].(Ref)
	if first.Num != 6 {
		t.Fatalf("first field is object %d, want 6 (the pre-existing text field)", first.Num)
	}
	if _, ok := fields[1].(Ref); !ok {
		t.Fatalf("second field is %T, want a reference", fields[1])
	}
}

func TestPrepareXrefStream(t *testing.T) {
	prep, err := Prepare(xrefStreamPDF(t), Options{Hash: HashSHA256})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	signed, err := prep.Assemble(bytes.Repeat([]byte{0xAA}, 500))
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	f, _, fld, sig := findSigField(t, signed)
	if got := toName(fld["FT"]); got != "Sig" {
		t.Fatalf("/FT = %q, want Sig", got)
	}
	if _, ok := f.trailer["Prev"]; !ok {
		t.Fatal("the appended trailer has no /Prev pointing at the xref stream")
	}

	// Objects from the original revision must still resolve through /Prev.
	if _, err := f.resolve(4); err != nil {
		t.Fatalf("resolve original object 4: %v", err)
	}
	if br := intArray(t, sig["ByteRange"]); !slices.Equal(br, []int64{0, prep.ByteRange[1], prep.ByteRange[2], prep.ByteRange[3]}) {
		t.Fatalf("/ByteRange = %v, want %v", br, prep.ByteRange)
	}

	// The update keeps the cross-reference format of the source.
	if !f.xrefStream {
		t.Fatal("the update over an xref-stream file wrote a classic xref table")
	}
	if bytes.Contains(signed[len(xrefStreamPDF(t)):], []byte("\nxref\n")) {
		t.Fatal("the update contains a classic xref table")
	}
	_, _, obj, err := f.parseIndirectAt(f.startXref)
	if err != nil {
		t.Fatalf("parse the update's xref stream: %v", err)
	}
	st := obj.(*Stream)
	size, _ := toInt(st.Dict["Size"])
	if e, ok := f.xref[int(size)-1]; !ok || e.kind != xrefInFile || e.off != f.startXref {
		t.Fatalf("xref stream does not list itself: entry %+v, startxref %d", e, f.startXref)
	}

	// A second signature over the result chains two xref streams.
	prep2, err := Prepare(signed, Options{Hash: HashSHA256})
	if err != nil {
		t.Fatalf("second Prepare: %v", err)
	}
	signed2, err := prep2.Assemble(bytes.Repeat([]byte{0xBB}, 500))
	if err != nil {
		t.Fatalf("second Assemble: %v", err)
	}
	f2, err := newPDFFile(signed2)
	if err != nil {
		t.Fatal(err)
	}
	if !f2.xrefStream {
		t.Fatal("second update wrote a classic xref table")
	}
	for _, num := range []int{4, sigObjNum(t, f)} {
		if _, err := f2.resolve(num); err != nil {
			t.Fatalf("object %d lost after the second update: %v", num, err)
		}
	}
}

// sigObjNum returns the object number of the newest /Sig dictionary.
func sigObjNum(t *testing.T, f *pdfFile) int {
	t.Helper()
	best := -1
	for num := range f.xref {
		obj, err := f.resolve(num)
		if err != nil {
			continue
		}
		if d, ok := obj.(Dict); ok && toName(d["Type"]) == "Sig" && num > best {
			best = num
		}
	}
	if best < 0 {
		t.Fatal("no /Sig dictionary")
	}
	return best
}

func TestPrepareEncrypted(t *testing.T) {
	pdf := buildPDFWithTrailer(t, []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
		"<< /Filter /Standard /V 2 /R 3 /O (x) /U (y) /P -1 >>",
	}, " /Encrypt 4 0 R")

	if _, err := Prepare(pdf, Options{Hash: HashSHA256}); !errors.Is(err, ErrEncrypted) {
		t.Fatalf("Prepare error = %v, want ErrEncrypted", err)
	}
}

func TestAssemblePlaceholderTooSmall(t *testing.T) {
	prep, err := Prepare(simplePDF(t), Options{Hash: HashSHA256, PlaceholderSize: 1024})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if _, err := prep.Assemble(make([]byte, 2000)); !errors.Is(err, ErrPlaceholderTooSmall) {
		t.Fatalf("Assemble error = %v, want ErrPlaceholderTooSmall", err)
	}
}

func TestAssembleRejectsBadByteRange(t *testing.T) {
	prep, err := Prepare(simplePDF(t), Options{Hash: HashSHA256})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	cases := map[string][4]int64{
		"gap is not a hex string": {0, 0, 10, int64(len(prep.PDF)) - 10},
		"does not cover document": {0, prep.ByteRange[1], prep.ByteRange[2], 1},
		"negative value":          {-1, 0, 0, 0},
		"reversed gap":            {0, prep.ByteRange[2], prep.ByteRange[1], 0},
	}

	for name, br := range cases {
		if _, err := Assemble(prep.PDF, br, []byte{1}); !errors.Is(err, ErrNotPrepared) {
			t.Errorf("%s: error = %v, want ErrNotPrepared", name, err)
		}
	}
}

func TestSignedContentBounds(t *testing.T) {
	doc := []byte("0123456789")

	got, err := SignedContent(doc, [4]int64{0, 5, 5, 5})
	if err != nil {
		t.Fatalf("SignedContent: %v", err)
	}
	if string(got) != string(doc) {
		t.Fatalf("SignedContent = %q, want the whole document", got)
	}

	if _, err := SignedContent(doc, [4]int64{0, 5, 5, 100}); !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("error = %v, want ErrNotPrepared", err)
	}
}

func TestPrepareWithoutHasher(t *testing.T) {
	prep, err := Prepare(simplePDF(t), Options{Hash: HashGOST3411_2012_256})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prep.Digest != nil {
		t.Fatalf("Digest = %x, want nil when no hasher is available", prep.Digest)
	}

	// The content flow still works: an arbitrary CMS can be assembled.
	if _, err := prep.Assemble([]byte{0x30, 0x80, 0x00, 0x00}); err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	// The digest flow must refuse rather than sign an empty digest.
	_, err = SignPDF(context.Background(), testProvider{}, simplePDF(t), Options{Hash: HashGOST3411_2012_256})
	if !errors.Is(err, ErrNoHasher) {
		t.Fatalf("SignPDF error = %v, want ErrNoHasher", err)
	}
}

type testProvider struct{}

func (testProvider) SignDetachedHash(_ context.Context, digest []byte, _ HashAlgorithm) ([]byte, error) {
	return digest, nil
}

func TestObjectRoundTrip(t *testing.T) {
	src := []byte("<< /A 1 /B (x(y)z) /C [1 2 3] /D << /E /F >> /G 3 0 R /H <48656C6C6F> /I true /J null >>")

	p := &parser{buf: src}
	obj, err := p.parseObject()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	d, ok := obj.(Dict)
	if !ok {
		t.Fatalf("parsed %T, want a dictionary", obj)
	}
	if got, _ := toInt(d["A"]); got != 1 {
		t.Fatalf("/A = %v, want 1", d["A"])
	}
	if got := string(d["B"].(String)); got != "x(y)z" {
		t.Fatalf("/B = %q, want x(y)z", got)
	}
	if got := string(d["H"].(HexString)); got != "Hello" {
		t.Fatalf("/H = %q, want Hello", got)
	}
	if ref, ok := d["G"].(Ref); !ok || ref.Num != 3 || ref.Gen != 0 {
		t.Fatalf("/G = %v, want 3 0 R", d["G"])
	}

	out, err := serialize(d)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	p2 := &parser{buf: out}
	obj2, err := p2.parseObject()
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	out2, err := serialize(obj2)
	if err != nil {
		t.Fatalf("re-serialize: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("serialisation is not stable:\n%s\n%s", out, out2)
	}
}
