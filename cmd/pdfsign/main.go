//go:build (linux || darwin) && cgo

// Command pdfsign signs a PDF file with a CryptoPro key container and verifies
// the result.
//
// It is the local-agent flow of package pdfsign, end to end: the document gets
// a signature placeholder, the CMS is produced over exactly the bytes declared
// in /ByteRange, and the finished file is checked twice — with CryptoPro
// (CAdES over the signed bytes) and with poppler (pdfinfo/pdfssig), which knows
// nothing about this module.
//
//	pdfsign -in contract.pdf                     sign with the default certificate
//	pdfsign -in contract.pdf -pin 12345678
//	pdfsign -in contract.pdf -type T -tsa http://tsa.example/
//	pdfsign -in contract.pdf -prepare            prepare only, no token needed
//
// Without -out the result is written next to the input: contract.signed.pdf
// when signing, contract.prepared.pdf with -prepare.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vdryagunov/gocades"
	"github.com/vdryagunov/gocades/internal/pdfcheck"
	"github.com/vdryagunov/gocades/internal/pdfsign"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "pdfsign: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	in := flag.String("in", "", "input PDF (required)")
	out := flag.String("out", "", "output PDF (default: <input>.signed.pdf)")
	// The env value is not the flag default, or -h would print it. Prefer the
	// variable: a PIN on the command line is visible in ps.
	pin := flag.String("pin", "", "key PIN; prefer $CRYPTOPRO_PIN, a flag value is visible in ps")
	thumb := flag.String("thumbprint", os.Getenv("CRYPTOPRO_THUMBPRINT"),
		"signer certificate SHA-1 thumbprint, hex (default: $CRYPTOPRO_THUMBPRINT)")
	cadesType := flag.String("type", "BES", "CAdES type: BES, T or XLong")
	tsa := flag.String("tsa", "", "timestamp authority URL (required for -type T and XLong)")
	reason := flag.String("reason", "", "signature reason")
	location := flag.String("location", "", "signature location")
	contact := flag.String("contact", "", "signer contact info")
	signer := flag.String("signer", "", "signer name")
	field := flag.String("field", "", "signature field name (default: SignatureN)")
	prepareOnly := flag.Bool("prepare", false, "only prepare the document; no token is used")
	stampOn := flag.Bool("stamp", false, "draw a visible stamp into the signature field")
	stampFont := flag.String("stamp-font", "", "TrueType font for the stamp (default: first system font found)")
	stampCorner := flag.String("stamp-corner", "bl", "stamp corner: bl, br, tl or tr")
	stampPage := flag.Int("stamp-page", 0, "page for the stamp (default: last)")
	stampTitle := flag.String("stamp-title", "", "stamp headline (default: ДОКУМЕНТ ПОДПИСАН)")
	cmsOut := flag.String("cms-out", "", "also write the detached CMS to this file (interop debugging)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: pdfsign -in file.pdf [options]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *pin == "" {
		*pin = os.Getenv("CRYPTOPRO_PIN")
	}

	if *in == "" {
		flag.Usage()
		return errors.New("-in is required")
	}

	typ, err := parseType(*cadesType)
	if err != nil {
		return err
	}
	if !*prepareOnly && (typ == gocades.CadesT || typ == gocades.CadesXLongType1) && *tsa == "" {
		return fmt.Errorf("-type %s requires -tsa", *cadesType)
	}

	outPath := *out
	if outPath == "" {
		base := strings.TrimSuffix(*in, filepath.Ext(*in))
		if *prepareOnly {
			outPath = base + ".prepared.pdf"
		} else {
			outPath = base + ".signed.pdf"
		}
	}

	var stamp *pdfsign.Stamp
	if *stampOn || *stampFont != "" {
		font, path, err := loadStampFont(*stampFont)
		if err != nil {
			return err
		}
		corner, err := parseCorner(*stampCorner)
		if err != nil {
			return err
		}
		stamp = &pdfsign.Stamp{
			Font:   font,
			Corner: corner,
			Page:   *stampPage,
			Title:  *stampTitle,
		}
		fmt.Printf("stamp font: %s\n", path)
	}

	pdf, err := os.ReadFile(*in)
	if err != nil {
		return err
	}

	prepared, err := pdfsign.Prepare(pdf, pdfsign.Options{
		Reason:      *reason,
		Location:    *location,
		ContactInfo: *contact,
		SignerName:  *signer,
		FieldName:   *field,
		Stamp:       stamp,
	})
	if err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}

	fmt.Printf("input     : %s (%d bytes)\n", *in, len(pdf))
	fmt.Printf("prepared  : %d bytes, field %s\n", len(prepared.PDF), prepared.FieldName)
	fmt.Printf("/ByteRange: %v\n", prepared.ByteRange)

	if *prepareOnly {
		if err := os.WriteFile(outPath, prepared.PDF, 0o644); err != nil {
			return err
		}
		fmt.Printf("output    : %s (placeholder, no signature yet)\n", outPath)
		fmt.Println()
		fmt.Println("verification")
		return reportStructure(outPath)
	}

	cert, release, err := openSigner(*thumb, *pin)
	if err != nil {
		return err
	}
	defer release()

	subject, _ := cert.SubjectName()
	thumbprint, _ := cert.Thumbprint()
	fmt.Printf("signer    : %s\n", subject)
	fmt.Printf("thumbprint: %s\n", thumbprint)

	sd := gocades.NewSignedData()
	defer sd.Close()
	if *tsa != "" {
		sd.SetTSAAddress(*tsa)
	}
	sd.SetContent(prepared.SignedContent())

	cms, err := sd.SignCades(cert, typ, true)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if *cmsOut != "" {
		if err := os.WriteFile(*cmsOut, cms, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", *cmsOut, err)
		}
	}

	signed, err := prepared.Assemble(cms)
	if err != nil {
		return fmt.Errorf("assemble: %w", err)
	}
	if err := os.WriteFile(outPath, signed, 0o644); err != nil {
		return err
	}

	fmt.Printf("cms       : %d bytes, CAdES-%s, detached\n", len(cms), *cadesType)
	fmt.Printf("output    : %s (%d bytes)\n", outPath, len(signed))

	fmt.Println()
	fmt.Println("verification")
	if err := gocades.VerifyDetached(cms, prepared.SignedContent(), typ); err != nil {
		return fmt.Errorf("CryptoPro cannot verify its own signature: %w", err)
	}
	fmt.Println("  ok    CAdES over the /ByteRange bytes")

	if err := reportStructure(outPath); err != nil {
		return err
	}
	return reportSignatures(outPath)
}

// reportStructure re-reads the written document with poppler's pdfinfo. The
// tool is optional, so a missing binary is a note, not a failure.
func reportStructure(path string) error {
	if !pdfcheck.Available("pdfinfo") {
		fmt.Println("  skip  pdfinfo: install poppler-utils for an independent check")
		return nil
	}
	detail, err := pdfcheck.Info(path)
	if err != nil {
		return err
	}
	fmt.Printf("  ok    pdfinfo: %s\n", detail)
	return nil
}

// reportSignatures asks poppler's pdfsig whether it sees a signature field.
func reportSignatures(path string) error {
	if !pdfcheck.Available("pdfsig") {
		fmt.Println("  skip  pdfsig: install poppler-utils for an independent check")
		return nil
	}
	detail, err := pdfcheck.Signatures(path)
	if err != nil {
		return err
	}
	fmt.Printf("  ok    pdfsig: %s\n", detail)
	return nil
}

// openSigner opens the per-user store and selects the signer certificate. The
// returned function releases the certificates and the store.
func openSigner(thumbprint, pin string) (*gocades.Certificate, func(), error) {
	store, err := gocades.OpenStore(gocades.StoreCurrentUser, "My")
	if err != nil {
		return nil, nil, fmt.Errorf("open CurrentUser/My: %w", err)
	}

	certs, err := store.Certificates()
	if err != nil {
		store.Close()
		return nil, nil, err
	}

	release := func() {
		for _, c := range certs {
			c.Close()
		}
		store.Close()
	}

	cert, err := pickCertificate(certs, thumbprint)
	if err != nil {
		release()
		return nil, nil, err
	}

	if pin != "" {
		if err := cert.SetPIN(pin); err != nil {
			release()
			return nil, nil, fmt.Errorf("set PIN: %w", err)
		}
	}

	return cert, release, nil
}

// pickCertificate returns the certificate with the given thumbprint, or the
// first one that has a private key when no thumbprint is given.
func pickCertificate(certs []*gocades.Certificate, thumbprint string) (*gocades.Certificate, error) {
	want := normalizeHex(thumbprint)
	for _, c := range certs {
		if want != "" {
			got, err := c.Thumbprint()
			if err != nil || normalizeHex(got) != want {
				continue
			}
			return c, nil
		}
		if c.HasPrivateKey() {
			return c, nil
		}
	}
	if want != "" {
		return nil, fmt.Errorf("no certificate with thumbprint %s in CurrentUser/My", thumbprint)
	}
	return nil, errors.New("no certificate with a private key in CurrentUser/My")
}

func normalizeHex(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(s))
}

// loadStampFont reads the requested font, or the first one found in the
// default locations. It returns the font bytes and the path that was used.
func loadStampFont(path string) ([]byte, string, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", err
		}
		return data, path, nil
	}
	for _, candidate := range pdfsign.SystemFonts {
		if data, err := os.ReadFile(candidate); err == nil {
			return data, candidate, nil
		}
	}
	return nil, "", errors.New("no TrueType font found for the stamp, pass -stamp-font")
}

// parseCorner maps the -stamp-corner flag onto pdfsign.Corner.
func parseCorner(s string) (pdfsign.Corner, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "bl", "bottom-left":
		return pdfsign.StampBottomLeft, nil
	case "br", "bottom-right":
		return pdfsign.StampBottomRight, nil
	case "tl", "top-left":
		return pdfsign.StampTopLeft, nil
	case "tr", "top-right":
		return pdfsign.StampTopRight, nil
	}
	return 0, fmt.Errorf("unknown -stamp-corner %q: want bl, br, tl or tr", s)
}

// parseType maps the -type flag onto the CAdES type constants.
func parseType(s string) (gocades.CadesType, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "BES", "B-B":
		return gocades.CadesBES, nil
	case "T", "B-T":
		return gocades.CadesT, nil
	case "XLONG", "X-LONG", "XLONG1", "X-LONG-TYPE-1":
		return gocades.CadesXLongType1, nil
	}
	return 0, fmt.Errorf("unknown -type %q: want BES, T or XLong", s)
}
