// Package pdfcheck validates a PDF with tools that are not part of this
// module: poppler's pdfinfo and pdfsig.
//
// The pdfsign tests and the smoke test both need a verdict from an independent
// parser, because code that writes PDFs and reads them back with its own
// parser only proves that it agrees with itself. pdfinfo re-reads the
// cross-reference chain and the page tree, pdfsig re-reads the signature
// dictionary. Neither tool needs to understand GOST: a document they reject is
// malformed whatever the signature algorithm.
//
// Both tools ship in the poppler-utils package (Debian, AlmaLinux). They are
// optional: Available reports whether one is installed, so callers can print a
// hint and skip instead of failing.
package pdfcheck

import (
	"errors"
	"fmt"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrUnavailable wraps the error returned when the requested tool is not
// installed.
var ErrUnavailable = errors.New("pdfcheck: tool not installed")

var (
	// pagesRe and versionRe pick the two fields of pdfinfo output that are
	// stable across poppler versions.
	pagesRe   = regexp.MustCompile(`(?m)^Pages:\s+(\d+)`)
	versionRe = regexp.MustCompile(`(?m)^PDF version:\s+(\S+)`)

	// handlerRe picks the signature handler of the first signature, e.g.
	// "ETSI.CAdES.detached". poppler has called this line both "Signature
	// Handler" and "Signature Type" depending on the version.
	handlerRe = regexp.MustCompile(`(?m)Signature (?:Handler|Type):\s*(\S+)`)

	// sigBlockRe matches the "Signature #1:" header. Newer poppler also prints
	// a "Signature Field Name" line inside the block, older versions (the 21.x
	// in AlmaLinux 9) do not, so the header is what both have in common.
	sigBlockRe  = regexp.MustCompile(`(?m)^Signature #(\d+)`)
	fieldNameRe = regexp.MustCompile(`(?m)Signature Field Name`)
	noSigRe     = regexp.MustCompile(`(?i)does not contain any signatures`)
)

// Available reports whether tool is in PATH.
func Available(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// run executes tool with args and returns its combined output. The locale is
// forced to C so that the output is parsed reliably on a localised system.
func run(tool string, args ...string) (string, error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrUnavailable, tool)
	}

	cmd := exec.Command(path, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", tool, err)
	}
	return string(out), nil
}

// Info returns a one-line description produced by pdfinfo: the page count and
// the PDF version. A document pdfinfo refuses to open is reported as an error,
// so this doubles as a structural check of the incremental update written by
// package pdfsign.
func Info(path string) (string, error) {
	out, err := run("pdfinfo", path)
	if err != nil {
		return "", fmt.Errorf("pdfinfo rejected the document: %w", err)
	}

	pages, version := "", ""
	if m := pagesRe.FindStringSubmatch(out); m != nil {
		pages = m[1] + " page(s)"
	}
	if m := versionRe.FindStringSubmatch(out); m != nil {
		version = "PDF " + m[1]
	}

	switch {
	case pages != "" && version != "":
		return pages + ", " + version, nil
	case pages != "":
		return pages, nil
	default:
		return "parsed", nil
	}
}

// Signatures reports how many signature fields pdfsig recognises in path and
// which handler the first one declares.
//
// The exit status is ignored as long as a signature field is found: pdfsig
// cannot validate GOST chains, and "certificate not trusted" is not a broken
// document. What matters here is that an independent parser sees the field.
func Signatures(path string) (string, error) {
	count, out, err := signatures(path)
	if err != nil {
		return "", err
	}

	detail := fmt.Sprintf("%d signature(s)", count)
	if m := handlerRe.FindStringSubmatch(out); m != nil {
		detail += ", " + m[1]
	}
	return detail, nil
}

// SignatureCount returns how many signature fields pdfsig recognises in path.
func SignatureCount(path string) (int, error) {
	count, _, err := signatures(path)
	return count, err
}

func signatures(path string) (int, string, error) {
	out, _ := run("pdfsig", path)

	count := len(sigBlockRe.FindAllString(out, -1))
	if count == 0 {
		count = len(fieldNameRe.FindAllString(out, -1))
	}
	if count == 0 {
		if noSigRe.MatchString(out) {
			return 0, out, fmt.Errorf("pdfsig sees no signature in the document")
		}
		return 0, out, fmt.Errorf("pdfsig could not read the signature: %s", signatureLines(out))
	}
	return count, out, nil
}

// signatureLines returns the output lines that talk about signatures, for
// error messages. poppler writes unrelated warnings (for example the harmless
// "couldn't find default Firefox Folder" on AlmaLinux) to the same stream.
func signatureLines(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(strings.ToLower(line), "signature") {
			keep = append(keep, line)
		}
	}
	if len(keep) == 0 {
		return firstLine(s)
	}
	return strings.Join(keep, " | ")
}

// firstLine returns the first non-empty line of s, for error messages that
// would otherwise dump a whole tool transcript.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return "(no output)"
}

// Ink renders page 1 with pdftoppm at 72 dpi (one pixel per point) and counts
// the dark pixels inside a rectangle given in PDF coordinates: x and y of the
// lower-left corner, then width and height.
//
// It returns the number of dark pixels, the rectangle area in pixels, and the
// rendered page size in points. It is used to check that a signature
// appearance is actually drawn where it should be.
func Ink(path string, x, y, w, h float64) (ink, area int, pageW, pageH int, err error) {
	dir, err := os.MkdirTemp("", "pdfcheck-render-")
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer os.RemoveAll(dir)

	prefix := filepath.Join(dir, "page")
	if _, err := run("pdftoppm", "-png", "-r", "72", "-f", "1", "-l", "1",
		"-singlefile", path, prefix); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("pdftoppm: %w", err)
	}

	f, err := os.Open(prefix + ".png")
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer f.Close()

	img, err := png.Decode(f)
	if err != nil {
		return 0, 0, 0, 0, err
	}

	bounds := img.Bounds()
	pageW, pageH = bounds.Dx(), bounds.Dy()

	// PDF y grows upwards, image y grows downwards.
	x0, x1 := int(x), int(x+w)
	y0, y1 := int(y), int(y+h)
	if x0 < 0 {
		x0 = 0
	}
	if y0 < 0 {
		y0 = 0
	}
	if x1 > pageW {
		x1 = pageW
	}
	if y1 > pageH {
		y1 = pageH
	}

	for py := 0; py < pageH; py++ {
		pdfY := pageH - 1 - py
		if pdfY < y0 || pdfY >= y1 {
			continue
		}
		for px := x0; px < x1; px++ {
			area++
			r, g, b, _ := img.At(px, py).RGBA()
			// Rec. 601 luma, scaled to 0..255.
			luma := (299*int(r>>8) + 587*int(g>>8) + 114*int(b>>8)) / 1000
			if luma < 128 {
				ink++
			}
		}
	}

	return ink, area, pageW, pageH, nil
}
