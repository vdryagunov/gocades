package pdfsign

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vdryagunov/gocades/internal/pdfcheck"
)

// TestStampRenders renders the prepared document with poppler and compares the
// ink inside the stamp box against the same document without a stamp. This is
// the only check that proves the appearance stream is actually drawn, rather
// than merely present in the file.
func TestStampRenders(t *testing.T) {
	font := testStampFont(t)
	if !pdfcheck.Available("pdftoppm") {
		t.Skip("pdftoppm not installed (poppler-utils)")
	}

	plain, err := Prepare(simplePDF(t), Options{Hash: HashSHA256})
	if err != nil {
		t.Fatalf("Prepare without stamp: %v", err)
	}
	stamped, err := Prepare(simplePDF(t), Options{
		Hash:       HashSHA256,
		SignerName: "Иванов Иван Иванович",
		Reason:     "Согласование",
		Stamp:      &Stamp{Font: font},
	})
	if err != nil {
		t.Fatalf("Prepare with stamp: %v", err)
	}

	dir := t.TempDir()
	plainPath := filepath.Join(dir, "plain.pdf")
	stampedPath := filepath.Join(dir, "stamped.pdf")
	if err := os.WriteFile(plainPath, plain.PDF, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stampedPath, stamped.PDF, 0o644); err != nil {
		t.Fatal(err)
	}

	box := func(path string) (ink, area int) {
		t.Helper()
		ink, area, _, _, err := pdfcheck.Ink(path,
			defaultStampMargin, defaultStampMargin, defaultStampWidth, defaultStampHeight)
		if err != nil {
			t.Fatalf("Ink(%s): %v", filepath.Base(path), err)
		}
		return ink, area
	}

	inkPlain, area := box(plainPath)
	inkStamped, _ := box(stampedPath)

	if area == 0 {
		t.Fatal("the stamp box maps to an empty region")
	}

	// A framed box with a headline and two text lines covers well over 5% of
	// the area; a blank region is under 1%.
	const want = 5 // per cent
	added := inkStamped - inkPlain
	if got := 100 * added / area; got < want {
		t.Fatalf("the stamp added %d of %d box pixels (%d before), want at least %d per cent",
			added, area, inkPlain, want)
	} else if got > 60 {
		t.Fatalf("the stamp covers %d of %d box pixels, which looks like a filled block",
			added, area)
	}
}
