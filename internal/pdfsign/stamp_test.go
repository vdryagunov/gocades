package pdfsign

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"
)

// testStampFont returns a TrueType font usable by the stamp tests, or skips the
// test when the machine has none installed.
func testStampFont(t *testing.T) []byte {
	t.Helper()

	for _, p := range []string{
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
		"/usr/share/fonts/dejavu/DejaVuSans.ttf",
		"/usr/share/fonts/TTF/DejaVuSans.ttf",
		"/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
		"/System/Library/Fonts/Supplemental/Arial.ttf",
		"/Library/Fonts/Arial.ttf",
	} {
		if data, err := os.ReadFile(p); err == nil {
			return data
		}
	}

	t.Skip("no TrueType font installed")
	return nil
}

func TestStampRequiresFont(t *testing.T) {
	_, err := Prepare(simplePDF(t), Options{Stamp: &Stamp{}})
	if !errors.Is(err, ErrStampFont) {
		t.Fatalf("Prepare without a font: err = %v, want ErrStampFont", err)
	}
}

// TestGlyphBoundsMatchHeader checks the outline decoder against data that comes
// from the font itself: every glyph header stores the exact bounding box of the
// decoded points, so a mismatch means the flags or deltas were read wrongly.
func TestGlyphBoundsMatchHeader(t *testing.T) {
	f, err := parseTrueType(testStampFont(t))
	if err != nil {
		t.Fatalf("parseTrueType: %v", err)
	}

	const sample = "ДОКУМЕНТПОДПИСАНДата1234:.,АБВГабвгЁё"
	for _, r := range sample {
		gid, ok := f.glyph(r)
		if !ok {
			t.Fatalf("font has no glyph for %q", r)
		}

		wantMinX, wantMinY, wantMaxX, wantMaxY, ok := f.glyphBounds(gid)
		if !ok {
			continue // empty glyph such as a space
		}

		contours, err := f.rawContours(gid, 0)
		if err != nil {
			t.Fatalf("rawContours(%q): %v", r, err)
		}

		gotMinX, gotMinY := int32(1<<30), int32(1<<30)
		gotMaxX, gotMaxY := -int32(1<<30), -int32(1<<30)
		for _, c := range contours {
			for _, p := range c {
				gotMinX = min(gotMinX, p.x)
				gotMinY = min(gotMinY, p.y)
				gotMaxX = max(gotMaxX, p.x)
				gotMaxY = max(gotMaxY, p.y)
			}
		}

		// Composite glyphs go through a float transform, so allow 2 units of
		// rounding.
		const tolerance = 2
		if abs32(gotMinX-wantMinX) > tolerance || abs32(gotMinY-wantMinY) > tolerance ||
			abs32(gotMaxX-wantMaxX) > tolerance || abs32(gotMaxY-wantMaxY) > tolerance {
			t.Errorf("glyph %q (%d): decoded bbox [%d %d %d %d], header says [%d %d %d %d]",
				r, gid, gotMinX, gotMinY, gotMaxX, gotMaxY,
				wantMinX, wantMinY, wantMaxX, wantMaxY)
		}
	}
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

func TestStampAppearance(t *testing.T) {
	font := testStampFont(t)

	prep, err := Prepare(simplePDF(t), Options{
		Hash:        HashSHA256,
		SignerName:  "Иванов Иван Иванович",
		Reason:      "Согласование документа",
		SigningTime: time.Unix(1700000000, 0),
		Stamp:       &Stamp{Font: font},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	f, _, field, _ := findSigField(t, prep.PDF)

	// The widget must carry a real rectangle, not [0 0 0 0].
	rect, err := f.resolveArray(field["Rect"])
	if err != nil {
		t.Fatalf("/Rect: %v", err)
	}
	if len(rect) != 4 {
		t.Fatalf("/Rect has %d elements, want 4", len(rect))
	}
	var values [4]float64
	for i, o := range rect {
		v, ok := toFloat(o)
		if !ok {
			t.Fatalf("/Rect[%d] = %T, want a number", i, o)
		}
		values[i] = v
	}
	if values[2]-values[0] != defaultStampWidth || values[3]-values[1] != defaultStampHeight {
		t.Fatalf("/Rect = %v, want a %gx%g box", values, defaultStampWidth, defaultStampHeight)
	}
	if values[0] != defaultStampMargin || values[1] != defaultStampMargin {
		t.Fatalf("/Rect origin = (%g, %g), want (%g, %g) for the bottom-left corner",
			values[0], values[1], defaultStampMargin, defaultStampMargin)
	}

	// /AP /N must point at a Form XObject with a Type3 font.
	ap, err := f.resolveDict(field["AP"])
	if err != nil || ap == nil {
		t.Fatalf("/AP: %v", err)
	}
	appRef, ok := ap["N"].(Ref)
	if !ok {
		t.Fatalf("/AP /N = %T, want a reference", ap["N"])
	}
	appearance, err := f.resolve(appRef.Num)
	if err != nil {
		t.Fatalf("appearance: %v", err)
	}
	var appDict Dict
	switch v := appearance.(type) {
	case Dict:
		appDict = v
	case *Stream:
		appDict = v.Dict
	default:
		t.Fatalf("appearance is %T, want a stream", appearance)
	}
	if got := toName(appDict["Subtype"]); got != "Form" {
		t.Fatalf("appearance /Subtype = %q, want Form", got)
	}
	bbox, err := f.resolveArray(appDict["BBox"])
	if err != nil || len(bbox) != 4 {
		t.Fatalf("/BBox: %v (%d elements)", err, len(bbox))
	}

	resources, err := f.resolveDict(appDict["Resources"])
	if err != nil || resources == nil {
		t.Fatalf("appearance /Resources: %v", err)
	}
	fonts, err := f.resolveDict(resources["Font"])
	if err != nil || fonts == nil {
		t.Fatalf("/Resources /Font: %v", err)
	}
	fontRef, ok := fonts["F1"].(Ref)
	if !ok {
		t.Fatalf("/Resources /Font /F1 = %T, want a reference", fonts["F1"])
	}
	fontDict, err := f.resolveDict(fontRef)
	if err != nil {
		t.Fatalf("font dictionary: %v", err)
	}
	if got := toName(fontDict["Subtype"]); got != "Type3" {
		t.Fatalf("font /Subtype = %q, want Type3", got)
	}

	charProcs, err := f.resolveDict(fontDict["CharProcs"])
	if err != nil || len(charProcs) == 0 {
		t.Fatalf("/CharProcs: %v (%d entries)", err, len(charProcs))
	}
	if _, ok := fontDict["ToUnicode"].(Ref); !ok {
		t.Fatal("font has no /ToUnicode map")
	}

	// The signed bytes must still be intact.
	if !bytes.HasPrefix(prep.PDF, simplePDF(t)) {
		t.Fatal("the prepared document does not start with the original bytes")
	}
}

// TestStampCornerAndPage covers placement in all four corners.
func TestStampCornerAndPage(t *testing.T) {
	font := testStampFont(t)

	// Read the page size from the test document rather than hard-coding it.
	probe, err := Prepare(simplePDF(t), Options{Hash: HashSHA256, Stamp: &Stamp{Font: font}})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	probeFile, _, _, _ := findSigField(t, probe.PDF)
	rootRef := probeFile.trailer["Root"].(Ref)
	catalog, err := probeFile.rootCatalog(rootRef)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	_, pageDict, err := probeFile.selectPage(catalog, 0)
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	media, err := probeFile.mediaBox(pageDict)
	if err != nil {
		t.Fatalf("mediaBox: %v", err)
	}

	left := media[0] + defaultStampMargin
	bottom := media[1] + defaultStampMargin
	right := media[2] - defaultStampMargin - defaultStampWidth
	top := media[3] - defaultStampMargin - defaultStampHeight

	for _, tc := range []struct {
		corner Corner
		wantX  float64
		wantY  float64
	}{
		{StampBottomLeft, left, bottom},
		{StampBottomRight, right, bottom},
		{StampTopLeft, left, top},
		{StampTopRight, right, top},
	} {
		prep, err := Prepare(simplePDF(t), Options{
			Hash:  HashSHA256,
			Stamp: &Stamp{Font: font, Corner: tc.corner},
		})
		if err != nil {
			t.Fatalf("corner %d: %v", tc.corner, err)
		}

		f, _, field, _ := findSigField(t, prep.PDF)
		rect, err := f.resolveArray(field["Rect"])
		if err != nil || len(rect) != 4 {
			t.Fatalf("corner %d: /Rect: %v", tc.corner, err)
		}
		x, _ := toFloat(rect[0])
		y, _ := toFloat(rect[1])
		if x != tc.wantX || y != tc.wantY {
			t.Errorf("corner %d: origin (%g, %g), want (%g, %g)", tc.corner, x, y, tc.wantX, tc.wantY)
		}
	}
}

// TestStampPageOutOfRange checks that a page that does not exist is rejected.
func TestStampPageOutOfRange(t *testing.T) {
	font := testStampFont(t)

	_, err := Prepare(simplePDF(t), Options{
		Hash:  HashSHA256,
		Stamp: &Stamp{Font: font, Page: 7},
	})
	if !errors.Is(err, ErrInvalidPDF) {
		t.Fatalf("err = %v, want ErrInvalidPDF", err)
	}
}
