package pdfsign_test

import (
	"bytes"
	"context"
	"fmt"

	"github.com/vdryagunov/gocades/internal/pdfsign"
)

// stubSigner stands in for the CryptoPro CMS signer. A real implementation
// returns a DER-encoded CAdES message whose messageDigest is the digest.
type stubSigner struct{}

func (stubSigner) SignDetachedHash(_ context.Context, digest []byte, _ pdfsign.HashAlgorithm) ([]byte, error) {
	out := make([]byte, 0, len(digest)+4)
	out = append(out, 0x30, 0x82) // a stand-in DER SEQUENCE header
	out = append(out, digest...)
	return out, nil
}

// ExampleSignPDF shows the single-process flow used by a local signing agent.
func ExampleSignPDF() {
	doc := minimalPDF()

	signed, err := pdfsign.SignPDF(context.Background(), stubSigner{}, doc, pdfsign.Options{
		Hash:            pdfsign.HashSHA256,
		SignerName:      "Ivanov Ivan Ivanovich",
		Reason:          "Document approval",
		PlaceholderSize: 4096,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(len(signed) > len(doc))
	// Output: true
}

// ExamplePrepare shows the browser flow: the document is prepared and its
// digest is handed to the plug-in, which signs it on the token.
func ExamplePrepare() {
	prep, err := pdfsign.Prepare(minimalPDF(), pdfsign.Options{
		Hash: pdfsign.HashSHA256,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(prep.FieldName)
	fmt.Println(len(prep.Digest))

	// The CMS would come back from the browser here.
	signed, err := pdfsign.Assemble(prep.PDF, prep.ByteRange, []byte{0x30, 0x80, 0x00, 0x00})
	if err != nil {
		panic(err)
	}
	fmt.Println(len(signed) == len(prep.PDF))

	// Output:
	// Signature1
	// 32
	// true
}

// minimalPDF builds a one-page PDF with a classic cross-reference table.
func minimalPDF() []byte {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")

	offsets := make([]int, len(objects))
	for i, o := range objects {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}

	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, xref)

	return b.Bytes()
}
