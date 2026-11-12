package pdfsign

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// Corner selects the page corner the stamp is placed in.
type Corner int

const (
	// StampBottomLeft is the default corner.
	StampBottomLeft Corner = iota
	StampBottomRight
	StampTopLeft
	StampTopRight
)

// Stamp adds a visible appearance to the signature: a framed box with the
// signer, the signing time and the reason, drawn into the widget's /AP stream.
//
// The stamp is drawn with a Type3 font built from the glyph outlines of the
// supplied TrueType font. Nothing is embedded as a font program, so the
// document grows by a few kilobytes regardless of the font size; only the
// characters that actually appear are included.
//
// Font is required: the standard PDF base fonts carry no Cyrillic glyphs, and
// this package has no built-in font.
type Stamp struct {
	// Font is a glyf-based TrueType font program (.ttf). OpenType/CFF and
	// font collections are rejected with ErrStampFont.
	Font []byte

	// Width and Height of the box in points. Default 240x80.
	Width, Height float64

	// Margin from the page edges in points. Default 20.
	Margin float64

	// FontSize of the body text in points. Default 8.
	FontSize float64

	// Corner selects the page corner. Default StampBottomLeft.
	Corner Corner

	// Page places the stamp and the signature field on a 1-based page number.
	// Zero means the last page.
	Page int

	// Title overrides the headline. Default "ДОКУМЕНТ ПОДПИСАН".
	Title string
}

const (
	defaultStampWidth  = 240.0
	defaultStampHeight = 80.0
	defaultStampMargin = 20.0
	defaultStampFont   = 8.0
	stampPadding       = 6.0
)

// box returns the effective box size.
func (s *Stamp) box() (float64, float64) {
	w, h := s.Width, s.Height
	if w <= 0 {
		w = defaultStampWidth
	}
	if h <= 0 {
		h = defaultStampHeight
	}
	return w, h
}

// SystemFonts lists the locations SystemFont looks in, in order. They cover the
// usual Debian/Ubuntu, AlmaLinux/RHEL and macOS installations.
var SystemFonts = []string{
	"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",   // Debian, Ubuntu
	"/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf", // Fedora, RHEL, AlmaLinux
	"/usr/share/fonts/dejavu/DejaVuSans.ttf",
	"/usr/share/fonts/TTF/DejaVuSans.ttf",
	"/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
	"/usr/share/fonts/liberation-sans/LiberationSans-Regular.ttf",
	"/System/Library/Fonts/Supplemental/Arial.ttf", // macOS
	"/Library/Fonts/Arial.ttf",
}

// SystemFont returns the contents of the first readable font from SystemFonts,
// or nil when none is installed.
//
// It is a convenience for callers that only need a working stamp. Production
// code should pass the font it wants in Stamp.Font: the glyphs are rendered as
// vector outlines, so the sender and the recipient always see the same shapes,
// whatever fonts the viewer has.
func SystemFont() []byte {
	for _, path := range SystemFonts {
		if data, err := os.ReadFile(path); err == nil {
			return data
		}
	}
	return nil
}

// objAlloc hands out object numbers for the incremental update and appends the
// serialized objects to its body.
type objAlloc struct {
	append func(num, gen int, payload []byte)
	next   int
}

func (a *objAlloc) new() Ref {
	ref := Ref{Num: a.next}
	a.next++
	return ref
}

func (a *objAlloc) put(ref Ref, payload []byte) { a.append(ref.Num, ref.Gen, payload) }

// stream appends a stream object and returns its reference.
func (a *objAlloc) stream(dict Dict, data []byte) (Ref, error) {
	ref := a.new()

	d := cloneDict(dict)
	d["Length"] = Integer(len(data))
	head, err := serialize(d)
	if err != nil {
		return Ref{}, err
	}

	var buf bytes.Buffer
	buf.Write(head)
	buf.WriteString("\nstream\n")
	buf.Write(data)
	buf.WriteString("\nendstream")
	a.put(ref, buf.Bytes())

	return ref, nil
}

/* ------------------------------------------------------------------ */
/* layout                                                              */
/* ------------------------------------------------------------------ */

// stampLayout is the content of the box after wrapping.
type stampLayout struct {
	title     []string
	body      []string
	titleSize float64
	bodySize  float64
}

// stampBuilder accumulates the character codes used by the stamp, because the
// Type3 font can only be built once the full alphabet is known.
type stampBuilder struct {
	font  *ttFont
	codes map[rune]byte
	order []rune
}

func newStampBuilder(font []byte) (*stampBuilder, error) {
	if len(font) == 0 {
		return nil, fmt.Errorf("%w: Stamp.Font is required (the standard PDF fonts have no Cyrillic)", ErrStampFont)
	}
	f, err := parseTrueType(font)
	if err != nil {
		return nil, err
	}
	return &stampBuilder{font: f, codes: make(map[rune]byte)}, nil
}

// measure returns the width of s in points.
func (b *stampBuilder) measure(s string, size float64) (float64, error) {
	var total float64
	for _, r := range s {
		gid, ok := b.font.glyph(r)
		if !ok {
			return 0, fmt.Errorf("%w: font has no glyph for %q", ErrStampFont, r)
		}
		total += b.font.advance(gid)
	}
	return total * size / 1000, nil
}

// wrap breaks text into lines that fit maxWidth.
func (b *stampBuilder) wrap(text string, size, maxWidth float64) ([]string, error) {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil, nil
	}

	var lines []string
	cur := ""
	flush := func() {
		if cur != "" {
			lines = append(lines, cur)
			cur = ""
		}
	}

	for _, w := range words {
		candidate := w
		if cur != "" {
			candidate = cur + " " + w
		}
		width, err := b.measure(candidate, size)
		if err != nil {
			return nil, err
		}
		if width <= maxWidth {
			cur = candidate
			continue
		}

		flush()

		wordWidth, err := b.measure(w, size)
		if err != nil {
			return nil, err
		}
		if wordWidth <= maxWidth {
			cur = w
			continue
		}

		// A single word is wider than the box: break it by runes.
		for _, r := range w {
			candidate := cur + string(r)
			width, err := b.measure(candidate, size)
			if err != nil {
				return nil, err
			}
			if width > maxWidth && cur != "" {
				flush()
				cur = string(r)
				continue
			}
			cur = candidate
		}
	}
	flush()

	return lines, nil
}

// layout wraps the stamp text into the box.
func (b *stampBuilder) layout(opts Options, s *Stamp, when time.Time, inner float64) (*stampLayout, error) {
	bodySize := s.FontSize
	if bodySize <= 0 {
		bodySize = defaultStampFont
	}
	titleSize := math.Max(bodySize*1.5, bodySize+2)

	title := s.Title
	if title == "" {
		title = "ДОКУМЕНТ ПОДПИСАН"
	}

	titleLines, err := b.wrap(title, titleSize, inner)
	if err != nil {
		return nil, err
	}

	texts := make([]string, 0, 3)
	if opts.SignerName != "" {
		texts = append(texts, "Подписант: "+opts.SignerName)
	}
	texts = append(texts, "Дата: "+when.Format("02.01.2006 15:04"))
	if opts.Reason != "" {
		texts = append(texts, "Причина: "+opts.Reason)
	}

	var body []string
	for _, t := range texts {
		lines, err := b.wrap(t, bodySize, inner)
		if err != nil {
			return nil, err
		}
		body = append(body, lines...)
	}

	return &stampLayout{
		title:     titleLines,
		body:      body,
		titleSize: titleSize,
		bodySize:  bodySize,
	}, nil
}

/* ------------------------------------------------------------------ */
/* content stream                                                      */
/* ------------------------------------------------------------------ */

// encode maps a string to Type3 character codes, registering new characters.
func (b *stampBuilder) encode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		code, ok := b.codes[r]
		if !ok {
			if len(b.order) >= 255 {
				return nil, fmt.Errorf("%w: stamp uses more than 254 distinct characters", ErrStampFont)
			}
			code = byte(len(b.order) + 1)
			b.codes[r] = code
			b.order = append(b.order, r)
		}
		out = append(out, code)
	}
	return out, nil
}

// content renders the appearance stream body.
func (b *stampBuilder) content(l *stampLayout, boxW, boxH float64) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString("q\n")
	buf.WriteString("0.08 0.24 0.70 RG\n")

	// Outer and inner frame.
	buf.WriteString("2 w\n")
	fmt.Fprintf(&buf, "0.5 0.5 %s %s re S\n", pdfNum(boxW-1), pdfNum(boxH-1))
	buf.WriteString("0.75 w\n")
	fmt.Fprintf(&buf, "4 4 %s %s re S\n", pdfNum(boxW-8), pdfNum(boxH-8))

	buf.WriteString("0 0 0 rg\n")
	buf.WriteString("BT\n")

	y := boxH - stampPadding - l.titleSize*0.85

	for _, line := range l.title {
		if y < stampPadding {
			break
		}
		encoded, err := b.encode(line)
		if err != nil {
			return nil, err
		}
		width, err := b.measure(line, l.titleSize)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buf, "/F1 %s Tf\n", pdfNum(l.titleSize))
		fmt.Fprintf(&buf, "1 0 0 1 %s %s Tm\n", pdfNum((boxW-width)/2), pdfNum(y))
		fmt.Fprintf(&buf, "<%x> Tj\n", encoded)
		y -= l.titleSize * 1.35
	}

	// Separator under the headline.
	ruleY := y + l.titleSize*0.35
	buf.WriteString("ET\n")
	buf.WriteString("0.08 0.24 0.70 RG\n")
	buf.WriteString("0.75 w\n")
	fmt.Fprintf(&buf, "%s %s m %s %s l S\n",
		pdfNum(stampPadding+2), pdfNum(ruleY), pdfNum(boxW-stampPadding-2), pdfNum(ruleY))

	buf.WriteString("0 0 0 rg\n")
	buf.WriteString("BT\n")

	y = ruleY - l.bodySize*1.6
	leading := l.bodySize * 1.4
	for _, line := range l.body {
		if y < stampPadding {
			break
		}
		encoded, err := b.encode(line)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buf, "/F1 %s Tf\n", pdfNum(l.bodySize))
		fmt.Fprintf(&buf, "1 0 0 1 %s %s Tm\n", pdfNum(stampPadding+2), pdfNum(y))
		fmt.Fprintf(&buf, "<%x> Tj\n", encoded)
		y -= leading
	}

	buf.WriteString("ET\n")
	buf.WriteString("Q\n")

	return buf.Bytes(), nil
}

/* ------------------------------------------------------------------ */
/* Type3 font                                                          */
/* ------------------------------------------------------------------ */

// buildFont appends the Type3 font objects and returns the font reference.
func (b *stampBuilder) buildFont(alloc *objAlloc) (Ref, error) {
	charProcs := make(Dict, len(b.order))
	widths := make(Array, 0, len(b.order))
	diff := make(Array, 0, len(b.order)+1)
	diff = append(diff, Integer(1))

	minX, minY := math.Inf(1), math.Inf(1)
	maxX, maxY := math.Inf(-1), math.Inf(-1)

	for i, r := range b.order {
		gid, _ := b.font.glyph(r)

		contours, err := b.font.contours(gid)
		if err != nil {
			return Ref{}, err
		}

		width := b.font.advance(gid)
		body := fmt.Sprintf("%s 0 d0\n", pdfNum(width))
		if path := glyphPath(contours); path != "" {
			body += path
		}

		ref, err := alloc.stream(Dict{}, []byte(body))
		if err != nil {
			return Ref{}, err
		}

		name := Name(fmt.Sprintf("g%d", i+1))
		charProcs[string(name)] = ref
		diff = append(diff, name)
		widths = append(widths, Real(width))

		for _, c := range contours {
			for _, p := range c {
				minX = math.Min(minX, float64(p.x))
				maxX = math.Max(maxX, float64(p.x))
				minY = math.Min(minY, float64(p.y))
				maxY = math.Max(maxY, float64(p.y))
			}
		}
	}

	toUnicode, err := alloc.stream(Dict{}, b.toUnicodeCMap())
	if err != nil {
		return Ref{}, err
	}

	bbox := Array{Integer(0), Integer(-200), Integer(1000), Integer(800)}
	if !math.IsInf(minX, 1) {
		bbox = Array{
			Real(math.Floor(minX)), Real(math.Floor(minY)),
			Real(math.Ceil(maxX)), Real(math.Ceil(maxY)),
		}
	}

	fontRef := alloc.new()
	payload, err := serialize(Dict{
		"Type":       Name("Font"),
		"Subtype":    Name("Type3"),
		"FontBBox":   bbox,
		"FontMatrix": Array{Real(0.001), Integer(0), Integer(0), Real(0.001), Integer(0), Integer(0)},
		"CharProcs":  charProcs,
		"Encoding": Dict{
			"Type":        Name("Encoding"),
			"Differences": diff,
		},
		"FirstChar": Integer(1),
		"LastChar":  Integer(len(b.order)),
		"Widths":    widths,
		"Resources": Dict{},
		"ToUnicode": toUnicode,
	})
	if err != nil {
		return Ref{}, err
	}
	alloc.put(fontRef, payload)

	return fontRef, nil
}

// toUnicodeCMap maps the Type3 character codes back to Unicode so that the
// stamp text can still be copied and searched.
func (b *stampBuilder) toUnicodeCMap() []byte {
	var buf bytes.Buffer

	buf.WriteString("/CIDInit /ProcSet findresource begin\n")
	buf.WriteString("12 dict begin\nbegincmap\n")
	buf.WriteString("/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n")
	buf.WriteString("/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n")
	buf.WriteString("1 begincodespacerange\n<00> <FF>\nendcodespacerange\n")

	const chunk = 100
	for start := 0; start < len(b.order); start += chunk {
		end := start + chunk
		if end > len(b.order) {
			end = len(b.order)
		}
		fmt.Fprintf(&buf, "%d beginbfchar\n", end-start)
		for i := start; i < end; i++ {
			fmt.Fprintf(&buf, "<%02x> <", i+1)
			for _, unit := range utf16Units(b.order[i]) {
				fmt.Fprintf(&buf, "%04x", unit)
			}
			buf.WriteString(">\n")
		}
		buf.WriteString("endbfchar\n")
	}

	buf.WriteString("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n")
	return buf.Bytes()
}

// utf16Units encodes a rune as UTF-16 code units, which is what a ToUnicode
// CMap expects.
func utf16Units(r rune) []uint16 {
	if r < 0x10000 {
		return []uint16{uint16(r)}
	}
	r -= 0x10000
	return []uint16{uint16(0xD800 + (r >> 10)), uint16(0xDC00 + (r & 0x3FF))}
}

/* ------------------------------------------------------------------ */
/* glyph outlines                                                      */
/* ------------------------------------------------------------------ */

// glyphPath renders contours as PDF path operators followed by a fill.
func glyphPath(contours [][]rawPoint) string {
	if len(contours) == 0 {
		return ""
	}
	var b strings.Builder
	for _, c := range contours {
		appendContour(&b, c)
	}
	b.WriteString("f\n")
	return b.String()
}

// appendContour converts one TrueType contour (quadratic splines, on/off-curve
// points) into PDF path operators. PDF only has cubic Béziers, so every
// quadratic segment is elevated.
func appendContour(b *strings.Builder, pts []rawPoint) {
	n := len(pts)
	if n == 0 {
		return
	}

	// The contour must start on an on-curve point. TrueType allows it to start
	// with a control point, so rotate or synthesise a start point.
	if !pts[0].on {
		if pts[n-1].on {
			pts = append([]rawPoint{pts[n-1]}, pts[:n-1]...)
		} else {
			mid := rawPoint{
				x:  (pts[n-1].x + pts[0].x) / 2,
				y:  (pts[n-1].y + pts[0].y) / 2,
				on: true,
			}
			pts = append([]rawPoint{mid}, pts...)
		}
	}

	start := pts[0]
	cur := start
	fmt.Fprintf(b, "%d %d m\n", start.x, start.y)

	for i := 1; i < len(pts); i++ {
		p := pts[i]
		if p.on {
			fmt.Fprintf(b, "%d %d l\n", p.x, p.y)
			cur = p
			continue
		}

		// p is a control point.
		if i+1 < len(pts) {
			next := pts[i+1]
			if next.on {
				writeQuad(b, cur, p, next)
				cur = next
				i++
				continue
			}
			// Two consecutive control points: the implied on-curve point is
			// their midpoint.
			mid := rawPoint{x: (p.x + next.x) / 2, y: (p.y + next.y) / 2, on: true}
			writeQuad(b, cur, p, mid)
			cur = mid
			continue
		}

		// Trailing control point: curve back to the contour start.
		writeQuad(b, cur, p, start)
		cur = start
	}

	b.WriteString("h\n")
}

// writeQuad emits a quadratically curved segment as a cubic Bézier.
func writeQuad(b *strings.Builder, from, ctrl, to rawPoint) {
	cx := float64(ctrl.x)
	cy := float64(ctrl.y)
	x1 := float64(from.x) + 2*(cx-float64(from.x))/3
	y1 := float64(from.y) + 2*(cy-float64(from.y))/3
	x2 := float64(to.x) + 2*(cx-float64(to.x))/3
	y2 := float64(to.y) + 2*(cy-float64(to.y))/3
	fmt.Fprintf(b, "%s %s %s %s %d %d c\n",
		pdfNum(x1), pdfNum(y1), pdfNum(x2), pdfNum(y2), to.x, to.y)
}

// pdfNum formats a number for a content stream.
func pdfNum(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e9 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

/* ------------------------------------------------------------------ */
/* appearance                                                          */
/* ------------------------------------------------------------------ */

// buildAppearance renders the stamp into a Form XObject and returns its
// reference. boxW and boxH are the /Rect dimensions.
func buildStampAppearance(opts Options, s *Stamp, alloc *objAlloc, boxW, boxH float64) (Ref, error) {
	builder, err := newStampBuilder(s.Font)
	if err != nil {
		return Ref{}, err
	}

	when := opts.signingTime()
	inner := boxW - 2*(stampPadding+2)
	if inner <= 0 {
		return Ref{}, fmt.Errorf("%w: stamp box is too narrow for the padding", ErrStampFont)
	}

	layout, err := builder.layout(opts, s, when, inner)
	if err != nil {
		return Ref{}, err
	}

	// content assigns the Type3 character codes, so it must run before the font
	// is built from that alphabet.
	data, err := builder.content(layout, boxW, boxH)
	if err != nil {
		return Ref{}, err
	}

	fontRef, err := builder.buildFont(alloc)
	if err != nil {
		return Ref{}, err
	}

	return alloc.stream(Dict{
		"Type":     Name("XObject"),
		"Subtype":  Name("Form"),
		"FormType": Integer(1),
		"BBox":     Array{Integer(0), Integer(0), Real(boxW), Real(boxH)},
		"Resources": Dict{
			"Font": Dict{"F1": fontRef},
		},
	}, data)
}
