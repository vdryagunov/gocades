package pdfsign

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Object is a PDF object: nil (null), Null, Bool, Integer, Real, Name, String,
// HexString, Array, Dict, Ref or *Stream.
type Object interface{}

// Null is the PDF null object. A nil Object is treated as null as well.
type Null struct{}

// Bool is a PDF boolean.
type Bool bool

// Integer is a PDF integer.
type Integer int64

// Real is a PDF real number.
type Real float64

// Name is a PDF name object (written with a leading slash).
type Name string

// String is a PDF literal string.
type String []byte

// HexString is a PDF hexadecimal string.
type HexString []byte

// Array is a PDF array.
type Array []Object

// Dict is a PDF dictionary.
type Dict map[string]Object

// Ref is an indirect object reference.
type Ref struct {
	Num int
	Gen int
}

// Stream is a stream object. Streams are only ever read by this package; the
// incremental update copies references to them rather than their contents.
type Stream struct {
	Dict Dict
	Data []byte
}

func cloneDict(d Dict) Dict {
	out := make(Dict, len(d))
	for k, v := range d {
		out[k] = v
	}
	return out
}

func toInt(o Object) (int64, bool) {
	switch v := o.(type) {
	case Integer:
		return int64(v), true
	case Real:
		return int64(v), true
	}
	return 0, false
}

func toFloat(o Object) (float64, bool) {
	switch v := o.(type) {
	case Integer:
		return float64(v), true
	case Real:
		return float64(v), true
	}
	return 0, false
}

func toName(o Object) string {
	if n, ok := o.(Name); ok {
		return string(n)
	}
	return ""
}

/* ------------------------------------------------------------------ */
/* serialisation                                                       */
/* ------------------------------------------------------------------ */

func serialize(o Object) ([]byte, error) {
	var b bytes.Buffer
	if err := writeObject(&b, o); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeObject(b *bytes.Buffer, o Object) error {
	switch v := o.(type) {
	case nil, Null:
		b.WriteString("null")

	case Bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}

	case Integer:
		b.WriteString(strconv.FormatInt(int64(v), 10))

	case Real:
		b.WriteString(strconv.FormatFloat(float64(v), 'f', -1, 64))

	case Name:
		b.WriteByte('/')
		b.WriteString(encodeName(string(v)))

	case String:
		b.WriteByte('(')
		writeLiteralString(b, v)
		b.WriteByte(')')

	case HexString:
		b.WriteByte('<')
		writeHexString(b, v)
		b.WriteByte('>')

	case Array:
		b.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				b.WriteByte(' ')
			}
			if err := writeObject(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')

	case Dict:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		b.WriteString("<<")
		for _, k := range keys {
			b.WriteByte('/')
			b.WriteString(encodeName(k))
			b.WriteByte(' ')
			if err := writeObject(b, v[k]); err != nil {
				return err
			}
			b.WriteByte(' ')
		}
		b.WriteString(">>")

	case Ref:
		fmt.Fprintf(b, "%d %d R", v.Num, v.Gen)

	case *Stream:
		return fmt.Errorf("pdfsign: cannot serialise a stream object as a direct value")

	default:
		return fmt.Errorf("pdfsign: unsupported object type %T", o)
	}
	return nil
}

func encodeName(s string) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c > ' ' && c < 0x7F && !isDelim(c) && c != '#' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "#%02X", c)
	}
	return b.String()
}

func writeLiteralString(b *bytes.Buffer, s []byte) {
	for _, c := range s {
		switch c {
		case '(', ')', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if c < 0x20 || c > 0x7E {
				fmt.Fprintf(b, "\\%03o", c)
				continue
			}
			b.WriteByte(c)
		}
	}
}

func writeHexString(b *bytes.Buffer, s []byte) {
	const hexDigits = "0123456789ABCDEF"
	for _, c := range s {
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0F])
	}
}

// escapeLiteralText escapes ASCII text (a date, a field name) for a literal
// string. Text that may hold non-ASCII characters goes through
// escapeTextString instead.
func escapeLiteralText(s string) string {
	var b bytes.Buffer
	writeLiteralString(&b, []byte(s))
	return b.String()
}

// escapeTextString encodes free text (a reason, a name) as a PDF text string
// (ISO 32000-1, 7.9.2.2) and escapes it for a literal string. Printable ASCII
// is identical in PDFDocEncoding and is kept as is; anything else is written
// as UTF-16BE with a byte order mark, since raw UTF-8 bytes would be read as
// PDFDocEncoding and shown garbled.
func escapeTextString(s string) string {
	if isPDFDocASCII(s) {
		return escapeLiteralText(s)
	}
	units := utf16.Encode([]rune(s))
	raw := make([]byte, 2, 2+2*len(units))
	raw[0], raw[1] = 0xFE, 0xFF
	for _, u := range units {
		raw = append(raw, byte(u>>8), byte(u))
	}
	var b bytes.Buffer
	writeLiteralString(&b, raw)
	return b.String()
}

func isPDFDocASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 || c > 0x7E) && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// decodeTextString decodes a PDF text string. UTF-16BE with a byte order mark
// is decoded; anything else is returned as is, which is exact for ASCII.
func decodeTextString(raw []byte) string {
	if len(raw) < 2 || raw[0] != 0xFE || raw[1] != 0xFF {
		return string(raw)
	}
	raw = raw[2:]
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
	}
	return string(utf16.Decode(units))
}

/* ------------------------------------------------------------------ */
/* lexer / parser                                                      */
/* ------------------------------------------------------------------ */

func isSpace(c byte) bool {
	switch c {
	case 0x00, 0x09, 0x0A, 0x0C, 0x0D, 0x20:
		return true
	}
	return false
}

func isDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

type parser struct {
	buf []byte
	pos int
}

func (p *parser) eof() bool { return p.pos >= len(p.buf) }

// skipSpace advances over whitespace and comments.
func (p *parser) skipSpace() {
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		if isSpace(c) {
			p.pos++
			continue
		}
		if c == '%' {
			for p.pos < len(p.buf) && p.buf[p.pos] != '\n' && p.buf[p.pos] != '\r' {
				p.pos++
			}
			continue
		}
		return
	}
}

// hasKeyword reports whether the buffer starts with kw, delimited on the right.
func (p *parser) hasKeyword(kw string) bool {
	if !bytes.HasPrefix(p.buf[p.pos:], []byte(kw)) {
		return false
	}
	end := p.pos + len(kw)
	if end >= len(p.buf) {
		return true
	}
	c := p.buf[end]
	return isSpace(c) || isDelim(c)
}

func (p *parser) readNumberToken() string {
	start := p.pos
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		if (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.' {
			p.pos++
			continue
		}
		break
	}
	return string(p.buf[start:p.pos])
}

// readUint skips whitespace and reads a non-negative integer.
func (p *parser) readUint() (int64, bool) {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.buf) && p.buf[p.pos] >= '0' && p.buf[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start {
		return 0, false
	}
	v, err := strconv.ParseInt(string(p.buf[start:p.pos]), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseObject parses a single direct object.
func (p *parser) parseObject() (Object, error) {
	p.skipSpace()
	if p.eof() {
		return nil, io.ErrUnexpectedEOF
	}

	switch c := p.buf[p.pos]; c {
	case '/':
		return p.parseName(), nil
	case '(':
		return p.parseLiteralString()
	case '<':
		if p.pos+1 < len(p.buf) && p.buf[p.pos+1] == '<' {
			return p.parseDict()
		}
		return p.parseHexString()
	case '[':
		return p.parseArray()
	case ']', '>', ')', '}':
		return nil, fmt.Errorf("pdfsign: unexpected %q at offset %d", c, p.pos)
	}

	switch {
	case p.hasKeyword("true"):
		p.pos += 4
		return Bool(true), nil
	case p.hasKeyword("false"):
		p.pos += 5
		return Bool(false), nil
	case p.hasKeyword("null"):
		p.pos += 4
		return nil, nil
	}

	if isNumberStart(p.buf[p.pos]) {
		return p.parseNumberOrRef()
	}

	start := p.pos
	tok := p.readToken()
	return nil, fmt.Errorf("pdfsign: unexpected token %q at offset %d (start %d)", tok, p.pos, start)
}

func isNumberStart(c byte) bool {
	return (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'
}

func (p *parser) readToken() string {
	start := p.pos
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		if isSpace(c) || isDelim(c) {
			break
		}
		p.pos++
	}
	return string(p.buf[start:p.pos])
}

func (p *parser) parseNumberOrRef() (Object, error) {
	start := p.pos
	tok := p.readNumberToken()
	if tok == "" {
		p.pos = start
		return nil, fmt.Errorf("pdfsign: malformed number at offset %d", start)
	}

	if !bytes.ContainsRune([]byte(tok), '.') {
		if n, err := strconv.ParseInt(tok, 10, 64); err == nil {
			// Look ahead for "gen R"; restore the position if it is not a ref.
			save := p.pos
			p.skipSpace()
			genTok := p.readNumberToken()
			if genTok != "" && !bytes.ContainsRune([]byte(genTok), '.') {
				if g, err := strconv.ParseInt(genTok, 10, 64); err == nil {
					p.skipSpace()
					if p.hasKeyword("R") {
						p.pos++
						if n >= 0 && g >= 0 && n <= 0x7FFFFFFF {
							return Ref{Num: int(n), Gen: int(g)}, nil
						}
					}
				}
			}
			p.pos = save
			return Integer(n), nil
		}
	}

	f, err := strconv.ParseFloat(tok, 64)
	if err != nil {
		p.pos = start
		return nil, fmt.Errorf("pdfsign: malformed number %q at offset %d", tok, start)
	}
	return Real(f), nil
}

func (p *parser) parseName() Name {
	p.pos++ // '/'
	var out []byte
	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		if isSpace(c) || isDelim(c) {
			break
		}
		if c == '#' && p.pos+2 < len(p.buf) {
			hi, ok1 := unhexDigit(p.buf[p.pos+1])
			lo, ok2 := unhexDigit(p.buf[p.pos+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				p.pos += 3
				continue
			}
		}
		out = append(out, c)
		p.pos++
	}
	return Name(out)
}

func (p *parser) parseLiteralString() (Object, error) {
	p.pos++ // '('
	depth := 1
	var out []byte

	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		p.pos++

		switch c {
		case '\\':
			if p.eof() {
				return nil, io.ErrUnexpectedEOF
			}
			e := p.buf[p.pos]
			p.pos++
			switch e {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '(', ')', '\\':
				out = append(out, e)
			case '\r':
				if !p.eof() && p.buf[p.pos] == '\n' {
					p.pos++
				}
			case '\n':
				// line continuation
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for k := 0; k < 2 && !p.eof(); k++ {
						c2 := p.buf[p.pos]
						if c2 < '0' || c2 > '7' {
							break
						}
						v = v*8 + int(c2-'0')
						p.pos++
					}
					out = append(out, byte(v))
				} else {
					out = append(out, e)
				}
			}

		case '(':
			depth++
			out = append(out, c)

		case ')':
			depth--
			if depth == 0 {
				return String(out), nil
			}
			out = append(out, c)

		case '\r':
			if !p.eof() && p.buf[p.pos] == '\n' {
				p.pos++
			}
			out = append(out, '\n')

		default:
			out = append(out, c)
		}
	}
	return nil, io.ErrUnexpectedEOF
}

func (p *parser) parseHexString() (Object, error) {
	p.pos++ // '<'
	var out []byte
	var hi byte
	haveHi := false

	for p.pos < len(p.buf) {
		c := p.buf[p.pos]
		p.pos++
		if c == '>' {
			if haveHi {
				out = append(out, hi<<4)
			}
			return HexString(out), nil
		}
		if isSpace(c) {
			continue
		}
		v, ok := unhexDigit(c)
		if !ok {
			return nil, fmt.Errorf("pdfsign: invalid hex string at offset %d", p.pos-1)
		}
		if haveHi {
			out = append(out, hi<<4|v)
			haveHi = false
		} else {
			hi = v
			haveHi = true
		}
	}
	return nil, io.ErrUnexpectedEOF
}

func (p *parser) parseArray() (Object, error) {
	p.pos++ // '['
	var out Array
	for {
		p.skipSpace()
		if p.eof() {
			return nil, io.ErrUnexpectedEOF
		}
		if p.buf[p.pos] == ']' {
			p.pos++
			return out, nil
		}
		o, err := p.parseObject()
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
}

func (p *parser) parseDict() (Object, error) {
	p.pos += 2 // '<<'
	out := Dict{}
	for {
		p.skipSpace()
		if p.eof() {
			return nil, io.ErrUnexpectedEOF
		}
		if p.buf[p.pos] == '>' && p.pos+1 < len(p.buf) && p.buf[p.pos+1] == '>' {
			p.pos += 2
			return out, nil
		}
		if p.buf[p.pos] != '/' {
			return nil, fmt.Errorf("pdfsign: expected a dictionary key at offset %d", p.pos)
		}
		key := string(p.parseName())
		val, err := p.parseObject()
		if err != nil {
			return nil, err
		}
		out[key] = val
	}
}

func unhexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
