// Package pdfsign implements the PDF half of PAdES: it prepares a document
// with a signature placeholder, computes the digest over the declared
// /ByteRange, and inserts a detached CMS into /Contents.
//
// It is an internal helper for this module: it is not part of the public API
// and cannot be imported from other modules. It exists so that `cmd/smoke` and
// `cmd/pdfsign` can produce real PAdES signatures for external validators.
//
// It is pure Go and knows nothing about CryptoPro. Signing is injected, so the
// same code serves both deployment topologies.
//
// # Two flows
//
// The browser plug-in flow splits the work into two HTTP round trips: the
// backend prepares the document and returns a digest, the plug-in signs it on
// the token, and the backend assembles the result.
//
//	prep, err := pdfsign.Prepare(src, pdfsign.Options{
//		Hash: pdfsign.HashGOST3411_2012_256,
//		NewHash: gost34112012256.New, // any hash.Hash implementation
//	})
//	// ... send prep.Digest to the browser, receive the CMS back ...
//	signed, err := pdfsign.Assemble(prep.PDF, prep.ByteRange, cms)
//
// The local-agent flow runs in one process and signs the content directly,
// which avoids needing a Go GOST implementation at all:
//
//	prep, err := pdfsign.Prepare(src, pdfsign.Options{})
//	cms, err := gocades.SignDetached(cert, prep.SignedContent(), gocades.SignOptions{
//		Type: gocades.CadesBES,
//	})
//	signed, err := prep.Assemble(cms)
//
// Because Prepare records the exact /ByteRange, the bytes covered by the
// signature are identical before and after assembling: the CMS only ever
// replaces the zero-filled placeholder.
//
// # Document layout
//
// Prepare appends an incremental update; the original bytes are never
// rewritten. The update adds three objects (the signature dictionary, the
// signature widget and a new revision of the page) plus a new revision of the
// catalog or of the AcroForm object, then a classic cross-reference section
// whose /Prev points at the previous one. Both classic xref tables and PDF 1.5
// xref streams with object streams are readable.
//
// # Limitations
//
// The signature is invisible: the widget has an empty /Rect. Visible
// appearances, document timestamps (PAdES B-LT/LTA), DSS and encrypted
// documents are not implemented. Documents whose streams use filters other
// than FlateDecode are rejected with ErrInvalidPDF.
package pdfsign
