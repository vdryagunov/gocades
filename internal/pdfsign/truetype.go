package pdfsign

import "fmt"

// This file reads just enough of a TrueType font to draw the glyphs used by a
// stamp as PDF paths. The font is not embedded: every glyph is turned into a
// Type3 character procedure, so the output grows by a few kilobytes instead of
// the whole font file.
//
// Only glyf-based outlines are supported. OpenType fonts with CFF outlines
// ('OTTO') and font collections ('.ttc') are rejected with ErrStampFont; both
// would need a different outline decoder.

// rawPoint is a point of a glyph contour in font units.
type rawPoint struct {
	x, y int32
	on   bool
}

// ttFont is a parsed TrueType font.
type ttFont struct {
	unitsPerEm float64
	numGlyphs  int
	numHMac    int
	advances   []uint16 // one per glyph, font units
	glyf       []byte
	loca       []uint32
	cmap       map[rune]uint16
}

/* ------------------------------------------------------------------ */
/* table directory                                                     */
/* ------------------------------------------------------------------ */

// u16 and u32 read big-endian values, returning ok=false when the range is
// outside the buffer. Vendor fonts are not always well-formed, so every read
// is bounds-checked instead of trusting the table lengths.
func u16(b []byte, off int) (uint16, bool) {
	if off < 0 || off+2 > len(b) {
		return 0, false
	}
	return uint16(b[off])<<8 | uint16(b[off+1]), true
}

func u32(b []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(b) {
		return 0, false
	}
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 |
		uint32(b[off+2])<<8 | uint32(b[off+3]), true
}

func i16(b []byte, off int) (int16, bool) {
	v, ok := u16(b, off)
	return int16(v), ok
}

// table returns the bytes of a TrueType table.
func table(data []byte, tag string) ([]byte, bool) {
	numTables, ok := u16(data, 4)
	if !ok {
		return nil, false
	}
	for i := 0; i < int(numTables); i++ {
		rec := 12 + 16*i
		if rec+16 > len(data) {
			return nil, false
		}
		if string(data[rec:rec+4]) != tag {
			continue
		}
		off, ok := u32(data, rec+8)
		n, ok2 := u32(data, rec+12)
		if !ok || !ok2 {
			return nil, false
		}
		start, end := int(off), int(off)+int(n)
		if start < 0 || end > len(data) || start > end {
			return nil, false
		}
		return data[start:end], true
	}
	return nil, false
}

// parseTrueType parses the tables needed to measure and outline glyphs.
func parseTrueType(data []byte) (*ttFont, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("%w: font file is too short", ErrStampFont)
	}
	switch string(data[:4]) {
	case "ttcf":
		return nil, fmt.Errorf("%w: font collections (.ttc) are not supported, pass a single .ttf", ErrStampFont)
	case "OTTO":
		return nil, fmt.Errorf("%w: CFF-based OpenType is not supported, pass a glyf-based .ttf", ErrStampFont)
	}

	f := &ttFont{}

	head, ok := table(data, "head")
	if !ok {
		return nil, fmt.Errorf("%w: font has no head table", ErrStampFont)
	}
	unitsPerEm, ok := u16(head, 18)
	if !ok || unitsPerEm == 0 {
		return nil, fmt.Errorf("%w: font has an invalid unitsPerEm", ErrStampFont)
	}
	f.unitsPerEm = float64(unitsPerEm)
	indexToLoc, ok := i16(head, 50)
	if !ok {
		return nil, fmt.Errorf("%w: font has a truncated head table", ErrStampFont)
	}

	maxp, ok := table(data, "maxp")
	if !ok {
		return nil, fmt.Errorf("%w: font has no maxp table", ErrStampFont)
	}
	numGlyphs, ok := u16(maxp, 4)
	if !ok || numGlyphs == 0 {
		return nil, fmt.Errorf("%w: font has an invalid glyph count", ErrStampFont)
	}
	f.numGlyphs = int(numGlyphs)

	hhea, ok := table(data, "hhea")
	if !ok {
		return nil, fmt.Errorf("%w: font has no hhea table", ErrStampFont)
	}
	numHMac, ok := u16(hhea, 34)
	if !ok || numHMac == 0 || int(numHMac) > f.numGlyphs {
		return nil, fmt.Errorf("%w: font has an invalid horizontal metric count", ErrStampFont)
	}
	f.numHMac = int(numHMac)

	hmtx, ok := table(data, "hmtx")
	if !ok {
		return nil, fmt.Errorf("%w: font has no hmtx table", ErrStampFont)
	}
	f.advances = make([]uint16, f.numHMac)
	for i := 0; i < f.numHMac; i++ {
		adv, ok := u16(hmtx, 4*i)
		if !ok {
			return nil, fmt.Errorf("%w: font has a truncated hmtx table", ErrStampFont)
		}
		f.advances[i] = adv
	}

	f.glyf, ok = table(data, "glyf")
	if !ok {
		return nil, fmt.Errorf("%w: font has no glyf table", ErrStampFont)
	}
	loca, ok := table(data, "loca")
	if !ok {
		return nil, fmt.Errorf("%w: font has no loca table", ErrStampFont)
	}
	f.loca = make([]uint32, f.numGlyphs+1)
	if indexToLoc == 0 {
		// Short format: offsets are stored in units of two bytes.
		for i := range f.loca {
			v, ok := u16(loca, 2*i)
			if !ok {
				return nil, fmt.Errorf("%w: font has a truncated loca table", ErrStampFont)
			}
			f.loca[i] = uint32(v) * 2
		}
	} else {
		for i := range f.loca {
			v, ok := u32(loca, 4*i)
			if !ok {
				return nil, fmt.Errorf("%w: font has a truncated loca table", ErrStampFont)
			}
			f.loca[i] = v
		}
	}

	cmap, ok := table(data, "cmap")
	if !ok {
		return nil, fmt.Errorf("%w: font has no cmap table", ErrStampFont)
	}
	m, err := parseCmap(cmap)
	if err != nil {
		return nil, err
	}
	f.cmap = m

	return f, nil
}

/* ------------------------------------------------------------------ */
/* character map                                                       */
/* ------------------------------------------------------------------ */

// parseCmap builds the rune -> glyph index map, preferring the full Unicode
// subtables over the legacy Windows/Unicode-BMP one.
func parseCmap(cmap []byte) (map[rune]uint16, error) {
	numTables, ok := u16(cmap, 2)
	if !ok {
		return nil, fmt.Errorf("%w: cmap table is truncated", ErrStampFont)
	}

	bestScore := -1
	var best []byte

	for i := 0; i < int(numTables); i++ {
		rec := 4 + 8*i
		platform, ok := u16(cmap, rec)
		encoding, ok2 := u16(cmap, rec+2)
		off, ok3 := u32(cmap, rec+4)
		if !ok || !ok2 || !ok3 {
			return nil, fmt.Errorf("%w: cmap table is truncated", ErrStampFont)
		}
		start := int(off)
		if start < 0 || start+2 > len(cmap) {
			continue
		}
		format, _ := u16(cmap, start)

		// 4 = full Unicode (format 12), 3 = Unicode BMP (format 4).
		score := -1
		switch {
		case (platform == 3 || platform == 0) && format == 12:
			score = 4
		case platform == 3 && encoding == 1 && format == 4:
			score = 3
		case platform == 0 && format == 4:
			score = 2
		}
		if score > bestScore {
			bestScore = score
			best = cmap[start:]
		}
	}

	switch {
	case best == nil:
		return nil, fmt.Errorf("%w: font has no Unicode character map", ErrStampFont)
	case bestScore == 4:
		return parseCmapFormat12(best)
	default:
		return parseCmapFormat4(best)
	}
}

func parseCmapFormat4(b []byte) (map[rune]uint16, error) {
	segCountX2, ok := u16(b, 6)
	if !ok {
		return nil, fmt.Errorf("%w: cmap format 4 is truncated", ErrStampFont)
	}
	segCount := int(segCountX2) / 2
	if segCount == 0 {
		return nil, fmt.Errorf("%w: cmap format 4 has no segments", ErrStampFont)
	}

	endOff := 14
	startOff := endOff + 2*segCount + 2
	deltaOff := startOff + 2*segCount
	rangeOff := deltaOff + 2*segCount

	m := make(map[rune]uint16)
	for seg := 0; seg < segCount; seg++ {
		end, ok1 := u16(b, endOff+2*seg)
		start, ok2 := u16(b, startOff+2*seg)
		delta, ok3 := i16(b, deltaOff+2*seg)
		ro, ok4 := u16(b, rangeOff+2*seg)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return nil, fmt.Errorf("%w: cmap format 4 is truncated", ErrStampFont)
		}
		if start > end {
			continue
		}
		for c := int(start); c <= int(end); c++ {
			if c == 0xFFFF {
				continue
			}
			var gid uint16
			if ro == 0 {
				gid = uint16(int(c) + int(delta))
			} else {
				addr := rangeOff + 2*seg + int(ro) + 2*(c-int(start))
				v, ok := u16(b, addr)
				if !ok {
					continue
				}
				if v == 0 {
					continue
				}
				gid = uint16(int(v) + int(delta))
			}
			if gid != 0 {
				m[rune(c)] = gid
			}
		}
	}
	return m, nil
}

func parseCmapFormat12(b []byte) (map[rune]uint16, error) {
	nGroups, ok := u32(b, 12)
	if !ok {
		return nil, fmt.Errorf("%w: cmap format 12 is truncated", ErrStampFont)
	}
	const maxGroups = 1 << 20 // a corrupt count must not allocate unbounded
	if nGroups > maxGroups {
		return nil, fmt.Errorf("%w: cmap format 12 has an implausible group count", ErrStampFont)
	}

	m := make(map[rune]uint16)
	for g := 0; g < int(nGroups); g++ {
		base := 16 + 12*g
		start, ok1 := u32(b, base)
		end, ok2 := u32(b, base+4)
		gid, ok3 := u32(b, base+8)
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("%w: cmap format 12 is truncated", ErrStampFont)
		}
		if start > end || end > 0x10FFFF {
			continue
		}
		for c := start; c <= end; c++ {
			glyph := gid + (c - start)
			if glyph == 0 || glyph > 0xFFFF {
				continue
			}
			m[rune(c)] = uint16(glyph)
		}
	}
	return m, nil
}

/* ------------------------------------------------------------------ */
/* metrics and outlines                                                */
/* ------------------------------------------------------------------ */

// scale converts font units to the 1000-unit text space used by the Type3
// font.
func (f *ttFont) scale() float64 { return 1000 / f.unitsPerEm }

// glyph returns the glyph index for r.
func (f *ttFont) glyph(r rune) (uint16, bool) {
	gid, ok := f.cmap[r]
	if !ok || int(gid) >= f.numGlyphs {
		return 0, false
	}
	return gid, true
}

// advance returns the glyph advance in 1000-unit text space.
func (f *ttFont) advance(gid uint16) float64 {
	i := int(gid)
	if i >= f.numHMac {
		i = f.numHMac - 1
	}
	if i < 0 || i >= len(f.advances) {
		return 0
	}
	return float64(f.advances[i]) * f.scale()
}

// glyphData returns the raw glyf entry of a glyph.
func (f *ttFont) glyphData(gid uint16) ([]byte, error) {
	i := int(gid)
	if i < 0 || i+1 >= len(f.loca) {
		return nil, fmt.Errorf("%w: glyph %d is out of range", ErrStampFont, gid)
	}
	start, end := f.loca[i], f.loca[i+1]
	if start > end || int(end) > len(f.glyf) {
		return nil, fmt.Errorf("%w: glyph %d has a broken loca entry", ErrStampFont, gid)
	}
	return f.glyf[start:end], nil
}

// glyphBounds returns the bounding box recorded in the glyph header, in font
// units: xMin, yMin, xMax, yMax. ok is false for empty glyphs.
func (f *ttFont) glyphBounds(gid uint16) (minX, minY, maxX, maxY int32, ok bool) {
	data, err := f.glyphData(gid)
	if err != nil || len(data) < 10 {
		return 0, 0, 0, 0, false
	}
	x1, ok1 := i16(data, 2)
	y1, ok2 := i16(data, 4)
	x2, ok3 := i16(data, 6)
	y2, ok4 := i16(data, 8)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return 0, 0, 0, 0, false
	}
	return int32(x1), int32(y1), int32(x2), int32(y2), true
}

// contours returns the outline of a glyph in 1000-unit text space. Composite
// glyphs are expanded recursively.
func (f *ttFont) contours(gid uint16) ([][]rawPoint, error) {
	raw, err := f.rawContours(gid, 0)
	if err != nil {
		return nil, err
	}
	s := f.scale()
	out := make([][]rawPoint, 0, len(raw))
	for _, c := range raw {
		scaled := make([]rawPoint, len(c))
		for i, p := range c {
			scaled[i] = rawPoint{
				x:  int32(float64(p.x) * s),
				y:  int32(float64(p.y) * s),
				on: p.on,
			}
		}
		out = append(out, scaled)
	}
	return out, nil
}

func (f *ttFont) rawContours(gid uint16, depth int) ([][]rawPoint, error) {
	if depth > 8 {
		return nil, fmt.Errorf("%w: composite glyph nesting is too deep", ErrStampFont)
	}

	data, err := f.glyphData(gid)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil // blank glyph, e.g. space
	}

	nContours, ok := i16(data, 0)
	if !ok {
		return nil, fmt.Errorf("%w: glyph %d is truncated", ErrStampFont, gid)
	}
	if nContours >= 0 {
		return parseSimpleGlyph(data, int(nContours))
	}
	return f.parseCompositeGlyph(data, depth)
}

func parseSimpleGlyph(data []byte, nContours int) ([][]rawPoint, error) {
	if nContours == 0 {
		return nil, nil
	}

	endPts := make([]int, nContours)
	for i := range endPts {
		v, ok := u16(data, 10+2*i)
		if !ok {
			return nil, fmt.Errorf("%w: glyph contour table is truncated", ErrStampFont)
		}
		endPts[i] = int(v)
	}
	nPoints := endPts[nContours-1] + 1
	if nPoints <= 0 || nPoints > 1<<16 {
		return nil, fmt.Errorf("%w: glyph has an implausible point count", ErrStampFont)
	}

	pos := 10 + 2*nContours
	instrLen, ok := u16(data, pos)
	if !ok {
		return nil, fmt.Errorf("%w: glyph instructions are truncated", ErrStampFont)
	}
	pos += 2 + int(instrLen)

	flags := make([]byte, 0, nPoints)
	for len(flags) < nPoints {
		if pos >= len(data) {
			return nil, fmt.Errorf("%w: glyph flags are truncated", ErrStampFont)
		}
		fl := data[pos]
		pos++
		flags = append(flags, fl)
		if fl&0x08 != 0 { // REPEAT_FLAG
			if pos >= len(data) {
				return nil, fmt.Errorf("%w: glyph flags are truncated", ErrStampFont)
			}
			rep := int(data[pos])
			pos++
			for j := 0; j < rep && len(flags) < nPoints; j++ {
				flags = append(flags, fl)
			}
		}
	}

	xs := make([]int32, nPoints)
	var v int32
	for i := 0; i < nPoints; i++ {
		fl := flags[i]
		switch {
		case fl&0x02 != 0: // X_SHORT_VECTOR
			if pos >= len(data) {
				return nil, fmt.Errorf("%w: glyph x coordinates are truncated", ErrStampFont)
			}
			d := int32(data[pos])
			pos++
			if fl&0x10 == 0 {
				d = -d
			}
			v += d
		case fl&0x10 == 0:
			d, ok := i16(data, pos)
			if !ok {
				return nil, fmt.Errorf("%w: glyph x coordinates are truncated", ErrStampFont)
			}
			pos += 2
			v += int32(d)
		}
		xs[i] = v
	}

	ys := make([]int32, nPoints)
	v = 0
	for i := 0; i < nPoints; i++ {
		fl := flags[i]
		switch {
		case fl&0x04 != 0: // Y_SHORT_VECTOR
			if pos >= len(data) {
				return nil, fmt.Errorf("%w: glyph y coordinates are truncated", ErrStampFont)
			}
			d := int32(data[pos])
			pos++
			if fl&0x20 == 0 {
				d = -d
			}
			v += d
		case fl&0x20 == 0:
			d, ok := i16(data, pos)
			if !ok {
				return nil, fmt.Errorf("%w: glyph y coordinates are truncated", ErrStampFont)
			}
			pos += 2
			v += int32(d)
		}
		ys[i] = v
	}

	contours := make([][]rawPoint, 0, nContours)
	start := 0
	for _, end := range endPts {
		if end < start || end >= nPoints {
			return nil, fmt.Errorf("%w: glyph contour has a broken end point", ErrStampFont)
		}
		c := make([]rawPoint, 0, end-start+1)
		for i := start; i <= end; i++ {
			c = append(c, rawPoint{x: xs[i], y: ys[i], on: flags[i]&0x01 != 0})
		}
		contours = append(contours, c)
		start = end + 1
	}
	return contours, nil
}

func (f *ttFont) parseCompositeGlyph(data []byte, depth int) ([][]rawPoint, error) {
	const (
		argsAreWords   = 0x0001
		argsAreXY      = 0x0002
		weHaveScale    = 0x0008
		moreComponents = 0x0020
		weHaveXYScale  = 0x0040
		weHave2x2      = 0x0080
	)

	f2dot14 := func(v uint16) float64 { return float64(int16(v)) / 16384 }

	var out [][]rawPoint
	pos := 10

	for {
		flags, ok := u16(data, pos)
		pos += 2
		component, ok2 := u16(data, pos)
		pos += 2
		if !ok || !ok2 {
			return nil, fmt.Errorf("%w: composite glyph is truncated", ErrStampFont)
		}

		var a1, a2 int32
		if flags&argsAreWords != 0 {
			v1, ok1 := i16(data, pos)
			v2, ok2 := i16(data, pos+2)
			pos += 4
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("%w: composite glyph is truncated", ErrStampFont)
			}
			a1, a2 = int32(v1), int32(v2)
		} else {
			if pos+2 > len(data) {
				return nil, fmt.Errorf("%w: composite glyph is truncated", ErrStampFont)
			}
			a1, a2 = int32(int8(data[pos])), int32(int8(data[pos+1]))
			pos += 2
		}
		if flags&argsAreXY == 0 {
			return nil, fmt.Errorf("%w: composite glyph uses point matching", ErrStampFont)
		}

		xx, xy, yx, yy := 1.0, 0.0, 0.0, 1.0
		switch {
		case flags&weHaveScale != 0:
			v, ok := u16(data, pos)
			pos += 2
			if !ok {
				return nil, fmt.Errorf("%w: composite glyph is truncated", ErrStampFont)
			}
			xx, yy = f2dot14(v), f2dot14(v)
		case flags&weHaveXYScale != 0:
			vx, ok1 := u16(data, pos)
			vy, ok2 := u16(data, pos+2)
			pos += 4
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("%w: composite glyph is truncated", ErrStampFont)
			}
			xx, yy = f2dot14(vx), f2dot14(vy)
		case flags&weHave2x2 != 0:
			v1, ok1 := u16(data, pos)
			v2, ok2 := u16(data, pos+2)
			v3, ok3 := u16(data, pos+4)
			v4, ok4 := u16(data, pos+6)
			pos += 8
			if !ok1 || !ok2 || !ok3 || !ok4 {
				return nil, fmt.Errorf("%w: composite glyph is truncated", ErrStampFont)
			}
			xx, xy, yx, yy = f2dot14(v1), f2dot14(v2), f2dot14(v3), f2dot14(v4)
		}

		sub, err := f.rawContours(component, depth+1)
		if err != nil {
			return nil, err
		}
		for _, c := range sub {
			moved := make([]rawPoint, len(c))
			for i, p := range c {
				moved[i] = rawPoint{
					x:  int32(float64(p.x)*xx+float64(p.y)*yx) + a1,
					y:  int32(float64(p.x)*xy+float64(p.y)*yy) + a2,
					on: p.on,
				}
			}
			out = append(out, moved)
		}

		if flags&moreComponents == 0 {
			break
		}
	}

	return out, nil
}
