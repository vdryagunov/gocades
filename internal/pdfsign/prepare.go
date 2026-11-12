package pdfsign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash"
	"slices"
	"strings"
	"time"
)

const (
	// DefaultPlaceholderSize is the /Contents placeholder size in bytes. The
	// hex-encoded CMS must fit into it: 16384 bytes covers CAdES-BES/B-T with a
	// certificate chain. Raise it for CAdES-X Long Type 1 or larger chains.
	DefaultPlaceholderSize = 16384

	minPlaceholderSize = 1024
	maxPlaceholderSize = 1 << 20

	// byteRangeNumberWidth is the fixed width of every number in /ByteRange.
	// Fixed width means patching the numbers never changes the layout.
	byteRangeNumberWidth = 10
)

// Options configures PAdES signing.
type Options struct {
	// Hash selects the digest algorithm. Defaults to HashGOST3411_2012_256.
	//
	// When no hasher is available for it (a NewHash is required for GOST),
	// Prepare still succeeds but leaves Prepared.Digest nil: the content flow
	// (SignedContent + Assemble) works, the digest flow does not.
	Hash HashAlgorithm

	// NewHash overrides the digest implementation. Required for algorithms
	// without a pure-Go implementation (GOST R 34.11-2012).
	NewHash func() hash.Hash

	// FieldName is the AcroForm signature field name. Generated when empty.
	FieldName string

	// Reason, Location, ContactInfo and SignerName are written into the
	// signature dictionary when set.
	Reason      string
	Location    string
	ContactInfo string
	SignerName  string

	// SigningTime defaults to time.Now().
	SigningTime time.Time

	// PlaceholderSize is the /Contents placeholder size in bytes.
	PlaceholderSize int

	// Stamp, when non-nil, adds a visible appearance to the signature. It
	// requires a TrueType font (see Stamp.Font); without one Prepare fails with
	// ErrStampFont, because the standard PDF fonts have no Cyrillic glyphs.
	Stamp *Stamp
}

// Prepared is a document revision with a signature placeholder ready to be
// signed. It carries everything needed to assemble the result later, so it can
// be persisted between the browser signing step and the assembling step.
type Prepared struct {
	// PDF is the prepared document, with a zero-filled /Contents placeholder.
	PDF []byte
	// ByteRange is the /ByteRange array: offset1, length1, offset2, length2.
	ByteRange [4]int64
	// Digest is the digest of the bytes covered by ByteRange. It is nil when no
	// hasher is available for Hash.
	Digest []byte
	// Hash is the algorithm used to produce Digest.
	Hash HashAlgorithm
	// FieldName is the signature field name created in the AcroForm.
	FieldName string

	newHash func() hash.Hash
}

// Prepare appends a signature revision to pdf: a /Sig widget field, an
// AcroForm entry and a signature dictionary whose /Contents is a placeholder.
//
// The returned digest covers exactly the bytes that will remain unchanged once
// the CMS is inserted, so signing it is safe.
func Prepare(pdf []byte, opts Options) (*Prepared, error) {
	hashFactory, alg, haveHasher := opts.hashFactory()

	placeholder := opts.PlaceholderSize
	if placeholder == 0 {
		placeholder = DefaultPlaceholderSize
	}
	if placeholder < minPlaceholderSize || placeholder > maxPlaceholderSize {
		return nil, fmt.Errorf("pdfsign: PlaceholderSize must be between %d and %d bytes, got %d",
			minPlaceholderSize, maxPlaceholderSize, placeholder)
	}

	f, err := newPDFFile(pdf)
	if err != nil {
		return nil, err
	}
	if _, ok := f.trailer["Encrypt"]; ok {
		return nil, ErrEncrypted
	}

	rootRef, ok := f.trailer["Root"].(Ref)
	if !ok {
		return nil, fmt.Errorf("%w: trailer has no /Root reference", ErrInvalidPDF)
	}
	catalog, err := f.rootCatalog(rootRef)
	if err != nil {
		return nil, err
	}

	pageRef, pageDict, err := f.selectPage(catalog, stampPage(opts.Stamp))
	if err != nil {
		return nil, err
	}

	acroObjNum, acroGen, acroDict, err := f.acroFormFor(catalog)
	if err != nil {
		return nil, err
	}
	fields, err := f.resolveArray(acroDict["Fields"])
	if err != nil {
		return nil, err
	}

	fieldName := opts.FieldName
	if fieldName == "" {
		fieldName = f.uniqueFieldName(fields, "Signature")
	}

	// Object numbers. /Size is the next free number in a well-formed file.
	next := f.maxObjectNumber() + 1
	if size, ok := toInt(f.trailer["Size"]); ok && int(size) > next {
		next = int(size)
	}

	/* --- build the incremental update --- */

	prefix := make([]byte, len(pdf), len(pdf)+1)
	copy(prefix, pdf)
	if len(prefix) == 0 || (prefix[len(prefix)-1] != '\n' && prefix[len(prefix)-1] != '\r') {
		prefix = append(prefix, '\n')
	}
	base := int64(len(prefix))

	var body bytes.Buffer
	var entries []xrefOut

	appendObj := func(num, gen int, payload []byte) {
		entries = append(entries, xrefOut{num: num, gen: gen, off: base + int64(body.Len())})
		fmt.Fprintf(&body, "%d %d obj\n", num, gen)
		body.Write(payload)
		body.WriteString("\nendobj\n")
	}

	alloc := &objAlloc{append: appendObj, next: next}

	contentsHex := strings.Repeat("0", placeholder*2)
	// The /ByteRange fields are written blank and patched in place once the
	// offsets are known; the fixed width keeps the layout stable. Padding is
	// spaces rather than zeros so that strict parsers see plain integers.
	pad := strings.Repeat(" ", byteRangeNumberWidth)
	sigDict := "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached" +
		" /Contents <" + contentsHex + ">" +
		" /ByteRange [0 " + pad + " " + pad + " " + pad + "]" +
		" /M (" + escapeLiteralText(pdfDate(opts.signingTime())) + ")"
	if opts.Reason != "" {
		sigDict += " /Reason (" + escapeTextString(opts.Reason) + ")"
	}
	if opts.Location != "" {
		sigDict += " /Location (" + escapeTextString(opts.Location) + ")"
	}
	if opts.ContactInfo != "" {
		sigDict += " /ContactInfo (" + escapeTextString(opts.ContactInfo) + ")"
	}
	if opts.SignerName != "" {
		sigDict += " /Name (" + escapeTextString(opts.SignerName) + ")"
	}
	sigDict += " >>"

	placeholderToken := "<" + contentsHex + ">"
	tokenOffset := strings.Index(sigDict, placeholderToken)
	if tokenOffset < 0 {
		return nil, fmt.Errorf("pdfsign: internal error: placeholder token not found")
	}
	// Offsets are taken inside this revision's signature dictionary: an
	// earlier signature in the same file has an identical /ByteRange prefix.
	byteRangeMarker := "/ByteRange [0 "
	byteRangeOffset := strings.Index(sigDict, byteRangeMarker)
	if byteRangeOffset < 0 {
		return nil, fmt.Errorf("pdfsign: internal error: /ByteRange not found")
	}

	// The signature object must come first so its offset is known early; the
	// gap start is the position of the '<' that opens /Contents.
	sigRef := alloc.new()
	sigHeader := fmt.Sprintf("%d %d obj\n", sigRef.Num, 0)
	sigBodyOffset := int64(body.Len())
	appendObj(sigRef.Num, 0, []byte(sigDict))
	sigDictStart := base + sigBodyOffset + int64(len(sigHeader))
	gapStart := sigDictStart + int64(tokenOffset)
	byteRangePos := sigDictStart + int64(byteRangeOffset+len(byteRangeMarker))

	fieldRef := alloc.new()

	// A visible stamp is part of the same revision, so its appearance stream is
	// covered by the signature.
	var (
		stampBox   [4]float64
		haveStamp  bool
		appearance Ref
	)
	if opts.Stamp != nil {
		media, err := f.mediaBox(pageDict)
		if err != nil {
			return nil, err
		}
		box, err := stampRect(opts.Stamp, media)
		if err != nil {
			return nil, err
		}
		appearance, err = buildStampAppearance(opts, opts.Stamp, alloc, box[2]-box[0], box[3]-box[1])
		if err != nil {
			return nil, err
		}
		stampBox, haveStamp = box, true
	}

	rect := "[0 0 0 0]"
	if haveStamp {
		rect = fmt.Sprintf("[%s %s %s %s]",
			pdfNum(stampBox[0]), pdfNum(stampBox[1]), pdfNum(stampBox[2]), pdfNum(stampBox[3]))
	}
	fieldDict := fmt.Sprintf(
		"<< /Type /Annot /Subtype /Widget /FT /Sig /T (%s) /F 132 /Rect %s /P %d %d R /V %d 0 R",
		escapeTextString(fieldName), rect, pageRef.Num, pageRef.Gen, sigRef.Num)
	if haveStamp {
		fieldDict += fmt.Sprintf(" /AP << /N %d 0 R >>", appearance.Num)
	}
	fieldDict += " >>"
	appendObj(fieldRef.Num, 0, []byte(fieldDict))

	annots, err := f.resolveArray(pageDict["Annots"])
	if err != nil {
		return nil, err
	}
	newAnnots := make(Array, 0, len(annots)+1)
	newAnnots = append(newAnnots, annots...)
	newAnnots = append(newAnnots, fieldRef)

	pageCopy := cloneDict(pageDict)
	pageCopy["Annots"] = newAnnots
	pagePayload, err := serialize(pageCopy)
	if err != nil {
		return nil, err
	}
	appendObj(pageRef.Num, pageRef.Gen, pagePayload)

	newFields := make(Array, 0, len(fields)+1)
	newFields = append(newFields, fields...)
	newFields = append(newFields, fieldRef)

	acroCopy := cloneDict(acroDict)
	acroCopy["Fields"] = newFields
	acroCopy["SigFlags"] = Integer(3)

	if acroObjNum >= 0 {
		// /AcroForm is an indirect object: rewrite it, the catalog is untouched.
		acroPayload, err := serialize(acroCopy)
		if err != nil {
			return nil, err
		}
		appendObj(acroObjNum, acroGen, acroPayload)
	} else {
		catCopy := cloneDict(catalog)
		catCopy["AcroForm"] = acroCopy
		catPayload, err := serialize(catCopy)
		if err != nil {
			return nil, err
		}
		appendObj(rootRef.Num, rootRef.Gen, catPayload)
	}

	/* --- cross-reference section and trailer --- */

	xrefOff := base + int64(body.Len())

	// A file whose newest section is an xref stream gets one as well: the
	// classic table is legal there, but strict validators expect the
	// revisions to keep one cross-reference format.
	var xrefStreamRef Ref
	if f.xrefStream {
		xrefStreamRef = alloc.new()
		entries = append(entries, xrefOut{num: xrefStreamRef.Num, off: xrefOff})
	}

	trailer := Dict{
		"Size": Integer(alloc.next),
		"Root": rootRef,
	}
	if f.startXref > 0 {
		trailer["Prev"] = Integer(f.startXref)
	}
	if id, ok := f.trailer["ID"]; ok && id != nil {
		trailer["ID"] = id
	}
	if info, ok := f.trailer["Info"].(Ref); ok {
		trailer["Info"] = info
	}
	var xref bytes.Buffer
	if f.xrefStream {
		if err := writeXrefStream(&xref, xrefStreamRef, trailer, entries); err != nil {
			return nil, err
		}
	} else {
		trailerPayload, err := serialize(trailer)
		if err != nil {
			return nil, err
		}
		xref.WriteString("xref\n")
		for _, e := range entries {
			fmt.Fprintf(&xref, "%d 1\n%010d %05d n \n", e.num, e.off, e.gen)
		}
		xref.WriteString("trailer\n")
		xref.Write(trailerPayload)
	}
	xref.WriteString("\nstartxref\n")
	fmt.Fprintf(&xref, "%d\n", xrefOff)
	xref.WriteString("%%EOF\n")

	/* --- assemble the file and compute the digest --- */

	out := make([]byte, 0, len(prefix)+body.Len()+xref.Len())
	out = append(out, prefix...)
	out = append(out, body.Bytes()...)
	out = append(out, xref.Bytes()...)

	totalLen := int64(len(out))
	gapEnd := gapStart + 2 + int64(placeholder*2)
	if gapEnd > totalLen {
		return nil, fmt.Errorf("pdfsign: internal error: placeholder runs past the end of the document")
	}
	if out[gapStart] != '<' || out[gapEnd-1] != '>' {
		return nil, fmt.Errorf("pdfsign: internal error: /Contents placeholder is misplaced")
	}

	byteRange := [4]int64{0, gapStart, gapEnd, totalLen - gapEnd}

	// Patch the numbers in place. Every field has a fixed width, so the layout
	// and therefore gapStart stay valid.
	pos := byteRangePos
	if !bytes.HasPrefix(out[pos-int64(len(byteRangeMarker)):], []byte(byteRangeMarker)) {
		return nil, fmt.Errorf("pdfsign: internal error: /ByteRange is misplaced")
	}
	for i, v := range []int64{byteRange[1], byteRange[2], byteRange[3]} {
		s := fmt.Sprintf("%*d", byteRangeNumberWidth, v)
		if len(s) != byteRangeNumberWidth {
			return nil, fmt.Errorf("pdfsign: document is too large for a %d-digit /ByteRange field",
				byteRangeNumberWidth)
		}
		field := out[pos+int64(i*(byteRangeNumberWidth+1)):][:byteRangeNumberWidth]
		if !bytes.Equal(field, []byte(pad)) {
			return nil, fmt.Errorf("pdfsign: internal error: /ByteRange field %d is not blank", i+1)
		}
		copy(field, s)
	}

	var digest []byte
	if haveHasher {
		hasher := hashFactory()
		if _, err := hasher.Write(out[:gapStart]); err != nil {
			return nil, err
		}
		if _, err := hasher.Write(out[gapEnd:]); err != nil {
			return nil, err
		}
		digest = hasher.Sum(nil)
	}

	return &Prepared{
		PDF:       out,
		ByteRange: byteRange,
		Digest:    digest,
		Hash:      alg,
		FieldName: fieldName,
		newHash:   hashFactory,
	}, nil
}

// SignedContent returns the bytes covered by the signature: the document
// without the /Contents gap. Pass it to the verifier together with the CMS.
func (p *Prepared) SignedContent() []byte {
	out, err := SignedContent(p.PDF, p.ByteRange)
	if err != nil {
		return nil
	}
	return out
}

// Assemble inserts the CMS into the placeholder and returns the signed PDF.
//
// It fails with ErrPlaceholderTooSmall when the signature does not fit; raise
// Options.PlaceholderSize and prepare the document again.
func (p *Prepared) Assemble(cms []byte) ([]byte, error) {
	out, err := Assemble(p.PDF, p.ByteRange, cms)
	if err != nil {
		return nil, err
	}

	// The insert must not have touched the signed bytes.
	if p.newHash != nil {
		h := p.newHash()
		gapStart := p.ByteRange[0] + p.ByteRange[1]
		gapEnd := p.ByteRange[2]
		h.Write(out[:gapStart])
		h.Write(out[gapEnd:])
		if !bytes.Equal(h.Sum(nil), p.Digest) {
			return nil, fmt.Errorf("pdfsign: internal error: assembling modified the signed bytes")
		}
	}

	return out, nil
}

// SignedContent returns the bytes covered by a /ByteRange.
func SignedContent(pdf []byte, br [4]int64) ([]byte, error) {
	if br[0] < 0 || br[1] < 0 || br[2] < 0 || br[3] < 0 {
		return nil, fmt.Errorf("%w: negative /ByteRange value", ErrNotPrepared)
	}

	end1 := br[0] + br[1]
	end2 := br[2] + br[3]
	if br[2] < end1 || br[2] > int64(len(pdf)) || end1 > int64(len(pdf)) || end2 > int64(len(pdf)) {
		return nil, fmt.Errorf("%w: /ByteRange is out of bounds", ErrNotPrepared)
	}

	out := make([]byte, 0, br[1]+br[3])
	out = append(out, pdf[br[0]:end1]...)
	out = append(out, pdf[br[2]:end2]...)
	return out, nil
}

// Assemble writes a DER CMS into the /Contents placeholder of a prepared
// document. It is stateless so that a backend can persist only the prepared
// PDF and its /ByteRange between signing and assembling.
func Assemble(pdf []byte, br [4]int64, cms []byte) ([]byte, error) {
	if br[0] < 0 || br[1] < 0 || br[2] < 0 || br[3] < 0 {
		return nil, fmt.Errorf("%w: negative /ByteRange value", ErrNotPrepared)
	}

	gapStart := br[0] + br[1]
	gapEnd := br[2]

	if gapEnd <= gapStart+2 || gapEnd > int64(len(pdf)) {
		return nil, fmt.Errorf("%w: /ByteRange does not describe a /Contents gap", ErrNotPrepared)
	}
	if int64(len(pdf)) != gapEnd+br[3] {
		return nil, fmt.Errorf("%w: /ByteRange does not cover the whole document", ErrNotPrepared)
	}
	if pdf[gapStart] != '<' || pdf[gapEnd-1] != '>' {
		return nil, fmt.Errorf("%w: the /ByteRange gap is not a hex string", ErrNotPrepared)
	}

	hexLen := gapEnd - gapStart - 2
	encoded := hex.EncodeToString(cms)
	if int64(len(encoded)) > hexLen {
		return nil, fmt.Errorf("%w: signature is %d bytes, the placeholder holds %d",
			ErrPlaceholderTooSmall, len(cms), hexLen/2)
	}

	out := make([]byte, len(pdf))
	copy(out, pdf)

	// Zero the whole placeholder, then write the CMS at its start. Trailing
	// zero bytes are the PAdES convention for unused /Contents space.
	for i := gapStart + 1; i < gapEnd-1; i++ {
		out[i] = '0'
	}
	copy(out[gapStart+1:gapEnd-1], encoded)

	return out, nil
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

func (o Options) signingTime() time.Time {
	if o.SigningTime.IsZero() {
		return time.Now()
	}
	return o.SigningTime
}

// pdfDate renders a time as a PDF date string, e.g. D:20231114221320Z.
func pdfDate(t time.Time) string {
	return t.UTC().Format("D:20060102150405") + "Z"
}

func (f *pdfFile) rootCatalog(rootRef Ref) (Dict, error) {
	obj, err := f.resolve(rootRef.Num)
	if err != nil {
		return nil, err
	}
	d, ok := obj.(Dict)
	if !ok {
		return nil, fmt.Errorf("%w: /Root is not a dictionary", ErrInvalidPDF)
	}
	return d, nil
}

// acroFormFor returns the AcroForm dictionary together with the object number
// and generation that must be rewritten, or -1 when the dictionary is inline
// in the catalog.
func (f *pdfFile) acroFormFor(catalog Dict) (int, int, Dict, error) {
	switch v := catalog["AcroForm"].(type) {
	case Ref:
		obj, err := f.resolve(v.Num)
		if err != nil {
			return 0, 0, nil, err
		}
		d, ok := obj.(Dict)
		if !ok {
			return 0, 0, nil, fmt.Errorf("%w: /AcroForm is not a dictionary", ErrInvalidPDF)
		}
		return v.Num, v.Gen, d, nil

	case Dict:
		return -1, 0, v, nil

	case nil:
		return -1, 0, Dict{}, nil

	default:
		return 0, 0, nil, fmt.Errorf("%w: unsupported /AcroForm value %T", ErrInvalidPDF, v)
	}
}

type pageLeaf struct {
	ref  Ref
	dict Dict
}

// pages returns every /Type /Page leaf in document order.
func (f *pdfFile) pages(catalog Dict) ([]pageLeaf, error) {
	pagesRef, ok := catalog["Pages"].(Ref)
	if !ok {
		return nil, fmt.Errorf("%w: catalog has no /Pages reference", ErrInvalidPDF)
	}

	var pages []pageLeaf
	var walk func(ref Ref, depth int) error

	walk = func(ref Ref, depth int) error {
		if depth > 64 {
			return fmt.Errorf("%w: page tree is too deep", ErrInvalidPDF)
		}
		obj, err := f.resolve(ref.Num)
		if err != nil {
			return err
		}
		d, ok := obj.(Dict)
		if !ok {
			return fmt.Errorf("%w: page tree node %d is not a dictionary", ErrInvalidPDF, ref.Num)
		}
		if toName(d["Type"]) == "Page" {
			pages = append(pages, pageLeaf{ref: ref, dict: d})
			return nil
		}

		kids, err := f.resolveArray(d["Kids"])
		if err != nil {
			return err
		}
		for _, kid := range kids {
			kidRef, ok := kid.(Ref)
			if !ok {
				continue
			}
			if err := walk(kidRef, depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(pagesRef, 0); err != nil {
		return nil, err
	}
	return pages, nil
}

// selectPage returns a 1-based page, or the last one when page is zero.
func (f *pdfFile) selectPage(catalog Dict, page int) (Ref, Dict, error) {
	pages, err := f.pages(catalog)
	if err != nil {
		return Ref{}, nil, err
	}
	if len(pages) == 0 {
		return Ref{}, nil, ErrNoPages
	}
	if page <= 0 {
		page = len(pages)
	}
	if page > len(pages) {
		return Ref{}, nil, fmt.Errorf("%w: page %d was requested, the document has %d",
			ErrInvalidPDF, page, len(pages))
	}

	p := pages[page-1]
	return p.ref, p.dict, nil
}

// stampPage returns the page requested by the stamp, or zero for the last one.
func stampPage(s *Stamp) int {
	if s == nil {
		return 0
	}
	return s.Page
}

// mediaBox returns the page size in points. /MediaBox may be inherited from an
// ancestor in the page tree, so the /Parent chain is followed.
func (f *pdfFile) mediaBox(page Dict) ([4]float64, error) {
	var zero [4]float64
	d := page

	for depth := 0; depth < 64; depth++ {
		if v, ok := d["MediaBox"]; ok {
			arr, err := f.resolveArray(v)
			if err != nil {
				return zero, err
			}
			if len(arr) != 4 {
				return zero, fmt.Errorf("%w: /MediaBox is not a 4-element array", ErrInvalidPDF)
			}
			var box [4]float64
			for i, o := range arr {
				x, ok := toFloat(o)
				if !ok {
					return zero, fmt.Errorf("%w: /MediaBox has a non-numeric element", ErrInvalidPDF)
				}
				box[i] = x
			}
			if box[2] <= box[0] || box[3] <= box[1] {
				return zero, fmt.Errorf("%w: /MediaBox is empty", ErrInvalidPDF)
			}
			return box, nil
		}

		parent, ok := d["Parent"].(Ref)
		if !ok {
			break
		}
		obj, err := f.resolve(parent.Num)
		if err != nil {
			return zero, err
		}
		next, ok := obj.(Dict)
		if !ok {
			break
		}
		d = next
	}

	return zero, fmt.Errorf("%w: page has no /MediaBox", ErrInvalidPDF)
}

// stampRect places the stamp box in page coordinates and returns
// [x0 y0 x1 y1].
func stampRect(s *Stamp, media [4]float64) ([4]float64, error) {
	var zero [4]float64

	w, h := s.box()
	margin := s.Margin
	if margin <= 0 {
		margin = defaultStampMargin
	}

	pageW := media[2] - media[0]
	pageH := media[3] - media[1]
	if w > pageW-2*margin {
		w = pageW - 2*margin
	}
	if h > pageH-2*margin {
		h = pageH - 2*margin
	}
	if w <= 0 || h <= 0 {
		return zero, fmt.Errorf("%w: stamp box does not fit the page", ErrStampFont)
	}

	var x0, y0 float64
	switch s.Corner {
	case StampBottomRight:
		x0, y0 = media[2]-margin-w, media[1]+margin
	case StampTopLeft:
		x0, y0 = media[0]+margin, media[3]-margin-h
	case StampTopRight:
		x0, y0 = media[2]-margin-w, media[3]-margin-h
	default: // StampBottomLeft
		x0, y0 = media[0]+margin, media[1]+margin
	}

	return [4]float64{x0, y0, x0 + w, y0 + h}, nil
}

// uniqueFieldName returns baseN, the first name not used by an existing field.
func (f *pdfFile) uniqueFieldName(fields Array, base string) string {
	used := make(map[string]bool, len(fields))
	for _, fld := range fields {
		ref, ok := fld.(Ref)
		if !ok {
			continue
		}
		obj, err := f.resolve(ref.Num)
		if err != nil {
			continue
		}
		d, ok := obj.(Dict)
		if !ok {
			continue
		}
		switch t := d["T"].(type) {
		case String:
			used[decodeTextString(t)] = true
		case HexString:
			used[decodeTextString(t)] = true
		}
	}

	for i := 1; ; i++ {
		name := fmt.Sprintf("%s%d", base, i)
		if !used[name] {
			return name
		}
	}
}

// xrefOut is one object written by the incremental update.
type xrefOut struct {
	num, gen int
	off      int64
}

// writeXrefStream writes the update's cross-reference section as an
// uncompressed xref stream object; trailer supplies /Size, /Root, /Prev,
// /ID and /Info.
func writeXrefStream(w *bytes.Buffer, ref Ref, trailer Dict, entries []xrefOut) error {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b xrefOut) int { return a.num - b.num })

	offWidth := 1
	for _, e := range sorted {
		for e.off>>(8*offWidth) != 0 {
			offWidth++
		}
	}

	var index Array
	var data []byte
	for i, e := range sorted {
		if i > 0 && sorted[i-1].num == e.num {
			return fmt.Errorf("pdfsign: internal error: object %d written twice", e.num)
		}
		if n := len(index); n > 0 && index[n-2].(Integer)+index[n-1].(Integer) == Integer(e.num) {
			index[n-1] = index[n-1].(Integer) + 1
		} else {
			index = append(index, Integer(e.num), Integer(1))
		}
		data = append(data, xrefInFile)
		for b := offWidth - 1; b >= 0; b-- {
			data = append(data, byte(e.off>>(8*b)))
		}
		data = append(data, byte(e.gen>>8), byte(e.gen))
	}

	d := cloneDict(trailer)
	d["Type"] = Name("XRef")
	d["W"] = Array{Integer(1), Integer(offWidth), Integer(2)}
	d["Index"] = index
	d["Length"] = Integer(len(data))
	head, err := serialize(d)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%d %d obj\n", ref.Num, ref.Gen)
	w.Write(head)
	w.WriteString("\nstream\n")
	w.Write(data)
	w.WriteString("\nendstream\nendobj")
	return nil
}
