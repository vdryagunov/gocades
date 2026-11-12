package pdfsign

import "errors"

var (
	// ErrInvalidPDF is returned when the input is not a PDF this package can
	// read (missing header, broken cross-reference table, unsupported filters).
	ErrInvalidPDF = errors.New("pdfsign: invalid or unsupported PDF")

	// ErrEncrypted is returned for documents with an /Encrypt dictionary.
	ErrEncrypted = errors.New("pdfsign: encrypted documents are not supported")

	// ErrNoPages is returned when the page tree yields no pages.
	ErrNoPages = errors.New("pdfsign: document has no pages")

	// ErrPlaceholderTooSmall is returned when the CMS does not fit into the
	// /Contents placeholder. Raise Options.PlaceholderSize and sign again.
	ErrPlaceholderTooSmall = errors.New("pdfsign: signature does not fit the /Contents placeholder")

	// ErrNoHasher is returned when no digest implementation is available for
	// the requested algorithm.
	ErrNoHasher = errors.New("pdfsign: no digest implementation for the requested algorithm")

	// ErrNotPrepared is returned when the ByteRange does not describe a
	// prepared signature revision.
	ErrNotPrepared = errors.New("pdfsign: document is not a prepared signature revision")

	// ErrStampFont is returned when the visible stamp cannot be rendered: the
	// font is missing, unreadable, lacks a glyph, or uses an unsupported
	// outline format.
	ErrStampFont = errors.New("pdfsign: unusable stamp font")
)
