package pdfsign

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

const maxXrefSections = 128

// xref entry kinds.
const (
	xrefFree   = 0
	xrefInFile = 1
	xrefInStm  = 2
)

type xrefEntry struct {
	kind int
	off  int64
	gen  int
	stm  int
	idx  int
}

type pdfFile struct {
	buf       []byte
	xref      map[int]xrefEntry
	trailer   Dict
	cache     map[int]Object
	objStms   map[int]map[int]Object
	startXref int64
	// xrefStream is true when the newest section is a cross-reference
	// stream; the incremental update then uses one too.
	xrefStream bool
}

func newPDFFile(buf []byte) (*pdfFile, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrInvalidPDF)
	}
	head := bytes.TrimLeft(buf, "\x00\t\r\n\x0c ")
	if !bytes.HasPrefix(head, []byte("%PDF-")) {
		return nil, fmt.Errorf("%w: missing %%PDF- header", ErrInvalidPDF)
	}

	start, err := findStartXref(buf)
	if err != nil {
		return nil, err
	}

	f := &pdfFile{
		buf:       buf,
		xref:      map[int]xrefEntry{},
		trailer:   Dict{},
		cache:     map[int]Object{},
		objStms:   map[int]map[int]Object{},
		startXref: start,
	}

	seen := map[int64]bool{}
	off := start
	for i := 0; off >= 0 && i < maxXrefSections; i++ {
		if seen[off] {
			break
		}
		seen[off] = true

		tr, err := f.readXrefSection(off)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			f.xrefStream = toName(tr["Type"]) == "XRef"
		}
		mergeTrailer(f.trailer, tr)

		// Hybrid-reference files point at an additional xref stream.
		if xs, ok := toInt(tr["XRefStm"]); ok && !seen[xs] {
			seen[xs] = true
			if tr2, err := f.readXrefSection(xs); err == nil {
				mergeTrailer(f.trailer, tr2)
			}
		}

		prev, ok := toInt(tr["Prev"])
		if !ok {
			break
		}
		off = prev
	}

	return f, nil
}

// mergeTrailer keeps the newest value for every key.
func mergeTrailer(dst, src Dict) {
	for k, v := range src {
		if _, ok := dst[k]; !ok {
			dst[k] = v
		}
	}
}

func findStartXref(buf []byte) (int64, error) {
	idx := bytes.LastIndex(buf, []byte("startxref"))
	if idx < 0 {
		return 0, fmt.Errorf("%w: no startxref keyword", ErrInvalidPDF)
	}
	p := &parser{buf: buf, pos: idx + len("startxref")}
	off, ok := p.readUint()
	if !ok {
		return 0, fmt.Errorf("%w: malformed startxref", ErrInvalidPDF)
	}
	if off < 0 || off >= int64(len(buf)) {
		return 0, fmt.Errorf("%w: startxref offset %d is out of range", ErrInvalidPDF, off)
	}
	return off, nil
}

func (f *pdfFile) readXrefSection(off int64) (Dict, error) {
	if off < 0 || off >= int64(len(f.buf)) {
		return nil, fmt.Errorf("%w: xref offset %d is out of range", ErrInvalidPDF, off)
	}

	p := &parser{buf: f.buf, pos: int(off)}
	p.skipSpace()
	if p.hasKeyword("xref") {
		return f.readClassicXref(p)
	}
	return f.readXrefStream(off)
}

func (f *pdfFile) readClassicXref(p *parser) (Dict, error) {
	p.pos += len("xref")

	local := map[int]xrefEntry{}
	for {
		p.skipSpace()
		if p.eof() {
			return nil, fmt.Errorf("%w: truncated xref table", ErrInvalidPDF)
		}
		if p.hasKeyword("trailer") {
			p.pos += len("trailer")
			break
		}

		start, ok := p.readUint()
		if !ok {
			return nil, fmt.Errorf("%w: malformed xref subsection at offset %d", ErrInvalidPDF, p.pos)
		}
		count, ok := p.readUint()
		if !ok {
			return nil, fmt.Errorf("%w: malformed xref subsection at offset %d", ErrInvalidPDF, p.pos)
		}

		for i := int64(0); i < count; i++ {
			p.skipSpace()
			entryOff, ok := p.readUint()
			if !ok {
				return nil, fmt.Errorf("%w: malformed xref entry at offset %d", ErrInvalidPDF, p.pos)
			}
			p.skipSpace()
			gen, ok := p.readUint()
			if !ok {
				return nil, fmt.Errorf("%w: malformed xref entry at offset %d", ErrInvalidPDF, p.pos)
			}
			p.skipSpace()
			if p.eof() {
				return nil, fmt.Errorf("%w: truncated xref entry", ErrInvalidPDF)
			}
			kind := p.buf[p.pos]
			p.pos++

			num := int(start + i)
			if _, exists := local[num]; exists {
				continue
			}
			switch kind {
			case 'n':
				local[num] = xrefEntry{kind: xrefInFile, off: entryOff, gen: int(gen)}
			case 'f':
				local[num] = xrefEntry{kind: xrefFree}
			}
		}
	}

	for num, e := range local {
		if _, exists := f.xref[num]; !exists {
			f.xref[num] = e
		}
	}

	obj, err := p.parseObject()
	if err != nil {
		return nil, err
	}
	d, ok := obj.(Dict)
	if !ok {
		return nil, fmt.Errorf("%w: malformed trailer", ErrInvalidPDF)
	}
	return d, nil
}

func (f *pdfFile) readXrefStream(off int64) (Dict, error) {
	_, _, obj, err := f.parseIndirectAt(off)
	if err != nil {
		return nil, err
	}
	st, ok := obj.(*Stream)
	if !ok {
		return nil, fmt.Errorf("%w: expected an xref stream at offset %d", ErrInvalidPDF, off)
	}
	if toName(st.Dict["Type"]) != "XRef" {
		return nil, fmt.Errorf("%w: expected /Type /XRef at offset %d", ErrInvalidPDF, off)
	}

	wArr, ok := st.Dict["W"].(Array)
	if !ok || len(wArr) < 3 {
		return nil, fmt.Errorf("%w: xref stream has no /W array", ErrInvalidPDF)
	}
	var w [3]int
	for i := 0; i < 3; i++ {
		n, ok := toInt(wArr[i])
		if !ok || n < 0 || n > 8 {
			return nil, fmt.Errorf("%w: unsupported /W entry", ErrInvalidPDF)
		}
		w[i] = int(n)
	}

	data, err := f.decode(st)
	if err != nil {
		return nil, err
	}

	sizeVal, _ := toInt(st.Dict["Size"])
	index := []int64{0, sizeVal}
	if idxArr, ok := st.Dict["Index"].(Array); ok {
		index = index[:0]
		for _, e := range idxArr {
			n, ok := toInt(e)
			if !ok {
				return nil, fmt.Errorf("%w: malformed /Index array", ErrInvalidPDF)
			}
			index = append(index, n)
		}
	}

	pos := 0
	for i := 0; i+1 < len(index); i += 2 {
		start, count := index[i], index[i+1]
		for j := int64(0); j < count; j++ {
			typ, _ := readField(data, &pos, w[0])
			if w[0] == 0 {
				typ = 1
			}
			f1, _ := readField(data, &pos, w[1])
			f2, _ := readField(data, &pos, w[2])

			num := int(start + j)
			if _, exists := f.xref[num]; exists {
				continue
			}
			switch typ {
			case xrefFree:
				f.xref[num] = xrefEntry{kind: xrefFree}
			case xrefInFile:
				f.xref[num] = xrefEntry{kind: xrefInFile, off: int64(f1), gen: int(f2)}
			case xrefInStm:
				f.xref[num] = xrefEntry{kind: xrefInStm, stm: int(f1), idx: int(f2)}
			}
		}
	}

	return st.Dict, nil
}

func readField(data []byte, pos *int, width int) (uint64, bool) {
	if width <= 0 {
		return 0, true
	}
	if *pos+width > len(data) {
		*pos = len(data)
		return 0, false
	}
	var v uint64
	for i := 0; i < width; i++ {
		v = v<<8 | uint64(data[*pos+i])
	}
	*pos += width
	return v, true
}

func (f *pdfFile) parseIndirectAt(off int64) (int, int, Object, error) {
	if off < 0 || off >= int64(len(f.buf)) {
		return 0, 0, nil, fmt.Errorf("%w: object offset %d is out of range", ErrInvalidPDF, off)
	}

	p := &parser{buf: f.buf, pos: int(off)}
	num, ok := p.readUint()
	if !ok {
		return 0, 0, nil, fmt.Errorf("%w: missing object number at offset %d", ErrInvalidPDF, off)
	}
	gen, ok := p.readUint()
	if !ok {
		return 0, 0, nil, fmt.Errorf("%w: missing generation at offset %d", ErrInvalidPDF, off)
	}
	p.skipSpace()
	if !p.hasKeyword("obj") {
		return 0, 0, nil, fmt.Errorf("%w: missing obj keyword at offset %d", ErrInvalidPDF, off)
	}
	p.pos += len("obj")

	obj, err := p.parseObject()
	if err != nil {
		return 0, 0, nil, err
	}

	if d, ok := obj.(Dict); ok {
		p.skipSpace()
		if p.hasKeyword("stream") {
			p.pos += len("stream")
			if !p.eof() && p.buf[p.pos] == '\r' {
				p.pos++
			}
			if !p.eof() && p.buf[p.pos] == '\n' {
				p.pos++
			}
			return int(num), int(gen), &Stream{Dict: d, Data: f.streamData(d, p.pos)}, nil
		}
	}

	return int(num), int(gen), obj, nil
}

func (f *pdfFile) streamData(d Dict, start int) []byte {
	if n, ok := toInt(d["Length"]); ok && n >= 0 {
		if end := int64(start) + n; end <= int64(len(f.buf)) {
			return f.buf[start:int(end)]
		}
	}

	idx := bytes.Index(f.buf[start:], []byte("endstream"))
	if idx < 0 {
		return f.buf[start:]
	}
	data := f.buf[start : start+idx]
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	return data
}

func (f *pdfFile) resolve(num int) (Object, error) {
	if o, ok := f.cache[num]; ok {
		return o, nil
	}

	e, ok := f.xref[num]
	if !ok {
		return nil, nil
	}

	switch e.kind {
	case xrefFree:
		return nil, nil

	case xrefInFile:
		_, _, obj, err := f.parseIndirectAt(e.off)
		if err != nil {
			return nil, err
		}
		f.cache[num] = obj
		return obj, nil

	case xrefInStm:
		m, err := f.objectStream(e.stm)
		if err != nil {
			return nil, err
		}
		obj := m[num]
		f.cache[num] = obj
		return obj, nil
	}

	return nil, fmt.Errorf("%w: unknown xref entry kind %d", ErrInvalidPDF, e.kind)
}

// resolveDict dereferences o and returns it as a dictionary.
func (f *pdfFile) resolveDict(o Object) (Dict, error) {
	if ref, ok := o.(Ref); ok {
		v, err := f.resolve(ref.Num)
		if err != nil {
			return nil, err
		}
		o = v
	}
	if o == nil {
		return nil, nil
	}
	d, ok := o.(Dict)
	if !ok {
		return nil, fmt.Errorf("%w: expected a dictionary, got %T", ErrInvalidPDF, o)
	}
	return d, nil
}

// resolveArray dereferences o and returns it as an array.
func (f *pdfFile) resolveArray(o Object) (Array, error) {
	if ref, ok := o.(Ref); ok {
		v, err := f.resolve(ref.Num)
		if err != nil {
			return nil, err
		}
		o = v
	}
	if o == nil {
		return nil, nil
	}
	a, ok := o.(Array)
	if !ok {
		return nil, fmt.Errorf("%w: expected an array, got %T", ErrInvalidPDF, o)
	}
	return a, nil
}

func (f *pdfFile) objectStream(stm int) (map[int]Object, error) {
	if m, ok := f.objStms[stm]; ok {
		return m, nil
	}

	obj, err := f.resolve(stm)
	if err != nil {
		return nil, err
	}
	s, ok := obj.(*Stream)
	if !ok {
		return nil, fmt.Errorf("%w: object %d is not an object stream", ErrInvalidPDF, stm)
	}
	if toName(s.Dict["Type"]) != "ObjStm" {
		return nil, fmt.Errorf("%w: object %d is not /Type /ObjStm", ErrInvalidPDF, stm)
	}

	n, _ := toInt(s.Dict["N"])
	first, _ := toInt(s.Dict["First"])

	data, err := f.decode(s)
	if err != nil {
		return nil, err
	}

	type pair struct{ num, off int }
	hdr := &parser{buf: data}
	pairs := make([]pair, 0, n)
	for i := int64(0); i < n; i++ {
		onum, ok := hdr.readUint()
		if !ok {
			break
		}
		ooff, ok := hdr.readUint()
		if !ok {
			break
		}
		pairs = append(pairs, pair{num: int(onum), off: int(ooff)})
	}

	out := make(map[int]Object, len(pairs))
	for _, pr := range pairs {
		start := int(first) + pr.off
		if start < 0 || start >= len(data) {
			continue
		}
		sub := &parser{buf: data, pos: start}
		o, err := sub.parseObject()
		if err != nil {
			continue
		}
		out[pr.num] = o
	}

	f.objStms[stm] = out
	return out, nil
}

// maxObjectNumber returns the highest object number known to the file.
func (f *pdfFile) maxObjectNumber() int {
	max := 0
	for n := range f.xref {
		if n > max {
			max = n
		}
	}
	return max
}

/* ------------------------------------------------------------------ */
/* stream decoding                                                     */
/* ------------------------------------------------------------------ */

func (f *pdfFile) decode(st *Stream) ([]byte, error) {
	data := st.Data

	var filters []Object
	switch v := st.Dict["Filter"].(type) {
	case Name:
		filters = []Object{v}
	case Array:
		filters = v
	}

	var parms []Object
	switch v := st.Dict["DecodeParms"].(type) {
	case Dict:
		parms = []Object{v}
	case Array:
		parms = v
	}

	for i, fo := range filters {
		name := toName(fo)
		switch name {
		case "FlateDecode", "Fl":
			inflated, err := inflate(data)
			if err != nil {
				return nil, err
			}
			data = inflated
		default:
			return nil, fmt.Errorf("%w: unsupported stream filter /%s", ErrInvalidPDF, name)
		}

		if i < len(parms) {
			if pd, ok := parms[i].(Dict); ok {
				unpredicted, err := applyPredictor(data, pd)
				if err != nil {
					return nil, err
				}
				data = unpredicted
			}
		}
	}

	return data, nil
}

func inflate(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: inflate: %v", ErrInvalidPDF, err)
	}
	defer zr.Close()

	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("%w: inflate: %v", ErrInvalidPDF, err)
	}
	return out, nil
}

func applyPredictor(data []byte, parms Dict) ([]byte, error) {
	predictor, _ := toInt(parms["Predictor"])
	if predictor <= 1 {
		return data, nil
	}
	if predictor < 10 {
		return nil, fmt.Errorf("%w: unsupported TIFF predictor %d", ErrInvalidPDF, predictor)
	}

	columns, _ := toInt(parms["Columns"])
	if columns <= 0 {
		columns = 1
	}
	colors, _ := toInt(parms["Colors"])
	if colors <= 0 {
		colors = 1
	}
	bpc, _ := toInt(parms["BitsPerComponent"])
	if bpc <= 0 {
		bpc = 8
	}

	bitsPerPixel := colors * bpc
	bpp := int((bitsPerPixel + 7) / 8)
	if bpp < 1 {
		bpp = 1
	}
	rowLen := int((columns*bitsPerPixel + 7) / 8)
	if rowLen <= 0 {
		return data, nil
	}

	stride := rowLen + 1
	rows := len(data) / stride
	out := make([]byte, 0, rows*rowLen)
	prev := make([]byte, rowLen)

	for r := 0; r < rows; r++ {
		filterType := data[r*stride]
		row := make([]byte, rowLen)
		copy(row, data[r*stride+1:(r+1)*stride])

		switch filterType {
		case 0: // none
		case 1: // sub
			for i := bpp; i < rowLen; i++ {
				row[i] += row[i-bpp]
			}
		case 2: // up
			for i := 0; i < rowLen; i++ {
				row[i] += prev[i]
			}
		case 3: // average
			for i := 0; i < rowLen; i++ {
				var left int
				if i >= bpp {
					left = int(row[i-bpp])
				}
				row[i] += byte((left + int(prev[i])) / 2)
			}
		case 4: // paeth
			for i := 0; i < rowLen; i++ {
				var a, c byte
				if i >= bpp {
					a = row[i-bpp]
					c = prev[i-bpp]
				}
				row[i] += paeth(a, prev[i], c)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported PNG predictor filter %d", ErrInvalidPDF, filterType)
		}

		out = append(out, row...)
		prev = row
	}

	return out, nil
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := absInt(p-int(a)), absInt(p-int(b)), absInt(p-int(c))
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
