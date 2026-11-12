//go:build (linux || darwin) && cgo

// Command smoke runs the CryptoPro Go port against the locally installed CSP.
//
// It is read-only until a PIN is supplied: without SMOKE_PIN every signing,
// decryption and key-import check is reported as SKIP. The PIN is never
// printed.
//
//	SMOKE_PIN=12345678 make smoke
//	SMOKE_PIN=12345678 make smoke THUMBPRINT=9f3c...
//	SMOKE_TSA=http://qs.cryptopro.ru/tsp/tsp.srf make smoke
//	SMOKE_PIN_PROMPT=1 make smoke   # no SetPIN: the CSP asks in its window
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/vdryagunov/gocades"
	"github.com/vdryagunov/gocades/internal/pdfcheck"
	"github.com/vdryagunov/gocades/internal/pdfsign"
)

// errKnownLimitation marks a check that fails because of a documented gap in
// the CryptoPro API surface, not because the port is broken. Such checks are
// reported as WARN and do not fail the run.
var errKnownLimitation = errors.New("known limitation")

// errSkipped marks a check that cannot run in the current mode.
var errSkipped = errors.New("skipped")

// nteSilentContext is NTE_SILENT_CONTEXT: the key was opened silently and the
// CSP needed to ask for the PIN.
const nteSilentContext = int32(-2146893790) // 0x80090022

type runner struct {
	pin     string
	tsa     string
	verbose bool

	// prompt runs the key checks without SetPIN, so the CSP asks for the PIN
	// in its own window.
	prompt bool

	// noCert is set when the store holds no certificate with a private key.
	// Certificate-dependent checks are then reported as SKIP instead of
	// failing, so the smoke test still works on a machine without a token.
	noCert bool

	passed  int
	failed  int
	skipped int
	warned  int
}

func (r *runner) step(name string, needPIN bool, fn func() (string, error)) {
	if needPIN && r.pin == "" && !r.prompt {
		r.skipped++
		fmt.Printf("  SKIP  %-42s set SMOKE_PIN or SMOKE_PIN_PROMPT=1 to enable\n", name)
		return
	}

	detail, err := fn()
	if err != nil {
		if errors.Is(err, errSkipped) {
			r.skipped++
			fmt.Printf("  SKIP  %-42s %v\n", name, err)
			return
		}
		var ce *gocades.Error
		if needPIN && r.prompt && errors.As(err, &ce) && ce.Code == nteSilentContext {
			r.warned++
			fmt.Printf("  WARN  %-42s opens the key silently, no PIN window: needs SetPIN\n", name)
			return
		}
		if errors.Is(err, errKnownLimitation) {
			r.warned++
			fmt.Printf("  WARN  %-42s %v\n", name, err)
			return
		}
		r.failed++
		fmt.Printf("  FAIL  %-42s %v\n", name, err)
		return
	}

	r.passed++
	fmt.Printf("  PASS  %-42s %s\n", name, detail)
}

func (r *runner) stepCert(name string, needPIN bool, fn func() (string, error)) {
	if r.noCert {
		r.skipped++
		fmt.Printf("  SKIP  %-42s no certificate with a private key\n", name)
		return
	}
	r.step(name, needPIN, fn)
}

func section(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
}

func main() {
	var (
		thumb   = flag.String("thumbprint", "", "signer certificate SHA-1 thumbprint (hex)")
		pin     = flag.String("pin", "", "key PIN; prefer $SMOKE_PIN, a flag value is visible in ps")
		tsa     = flag.String("tsa", os.Getenv("SMOKE_TSA"), "TSA URL for CAdES-T")
		verbose = flag.Bool("v", false, "print certificate details")
	)
	flag.Parse()
	// The env value is not the flag default, or -h would print it.
	if *pin == "" {
		*pin = os.Getenv("SMOKE_PIN")
	}

	r := &runner{pin: *pin, tsa: *tsa, verbose: *verbose, prompt: os.Getenv("SMOKE_PIN_PROMPT") == "1"}
	if r.prompt && r.pin != "" {
		fmt.Println("SMOKE_PIN_PROMPT=1 asks for the PIN in the CSP window; unset SMOKE_PIN")
		os.Exit(2)
	}

	fmt.Println("CryptoPro Go port — smoke test")
	fmt.Println(strings.Repeat("=", 60))

	section("Environment")

	r.step("CSP version", false, func() (string, error) {
		v, err := gocades.About{}.CSPVersion()
		if err != nil {
			return "", err
		}
		return v.String(), nil
	})

	r.step("CSP name", false, func() (string, error) {
		return gocades.About{}.CSPName(gocades.ProvGOST2012_256)
	})

	r.step("provider algorithms", false, func() (string, error) {
		algs, err := gocades.ProviderAlgorithms()
		if err != nil {
			return "", err
		}
		if len(algs) == 0 {
			return "", fmt.Errorf("no algorithms reported")
		}
		if r.verbose {
			for _, a := range algs {
				fmt.Printf("        %-12s id=0x%04x bits=%d..%d\n", a.Name, a.ID, a.MinBits, a.MaxBits)
			}
		}
		return fmt.Sprintf("%d algorithms", len(algs)), nil
	})

	r.step("Enroll: EnumContainers", false, func() (string, error) {
		name, err := gocades.About{}.CSPName(gocades.ProvGOST2012_256)
		if err != nil {
			return "", err
		}
		csp, err := gocades.NewEnrollCspInformationFromName(name)
		if err != nil {
			return "", err
		}
		conts, err := csp.EnumContainers()
		if err != nil {
			return "", err
		}
		if conts.Count() == 0 {
			return "0 containers", nil
		}
		c0, err := conts.Item(0)
		if err != nil {
			return "", err
		}
		keys, err := c0.Keys()
		if err != nil {
			return "", err
		}
		defer keys.Close()
		detail := fmt.Sprintf("%d containers, first FQCN=%q keys=%d",
			conts.Count(), c0.FQCN(), keys.Count())
		if keys.Count() > 0 {
			k0, err := keys.Item(0)
			if err != nil {
				return "", err
			}
			detail += fmt.Sprintf(" type=%d exportable=%v hasCert=%v",
				k0.Type(), k0.IsExportable(), k0.HasCertificate())
		}
		return detail, nil
	})

	r.step("CX509: CreateRequest PKCS#10", false, func() (string, error) {
		pin := r.pin
		if pin == "" {
			pin = "12345678"
		}
		cont := fmt.Sprintf("gocades-csr-%d", time.Now().UnixNano())
		key := &gocades.X509PrivateKey{
			ProviderType:  gocades.ProvGOST2012_256,
			ContainerName: cont,
			KeySpec:       gocades.ATKeyExchange,
			Exportable:    true,
			Silent:        true,
			Pin:           pin,
		}
		if err := key.Create(); err != nil {
			return "", err
		}
		defer func() { _ = key.Delete() }()

		dn := &gocades.X500DistinguishedName{}
		if err := dn.Encode("CN=gocades-smoke-csr,C=RU"); err != nil {
			return "", err
		}
		req := &gocades.X509CertificateRequestPkcs10{}
		if err := req.InitializeFromPrivateKey(gocades.ContextUser, key, ""); err != nil {
			return "", err
		}
		if err := req.SetSubject(dn); err != nil {
			return "", err
		}
		req.SetKeyUsage(gocades.KeyUsageDigitalSignature | gocades.KeyUsageNonRepudiation)
		enroll := &gocades.X509Enrollment{Silent: true}
		if err := enroll.InitializeFromRequest(req); err != nil {
			return "", err
		}
		der, err := enroll.CreateRequestDER()
		if err != nil {
			return "", err
		}
		if len(der) < 64 {
			return "", fmt.Errorf("request too short: %d", len(der))
		}
		return fmt.Sprintf("%d bytes, container=%s", len(der), key.ContainerName), nil
	})

	section("Store and certificates")

	store, err := gocades.OpenStore(gocades.StoreCurrentUser, "My")
	if err != nil {
		fmt.Printf("  FAIL  %-42s %v\n", "open CurrentUser/My", err)
		os.Exit(1)
	}
	defer store.Close()

	fmt.Printf("  INFO  %-42s %s/%s\n", "store", store.Location(), store.Name())

	certs, err := store.Certificates()
	if err != nil {
		fmt.Printf("  FAIL  %-42s %v\n", "enumerate certificates", err)
		os.Exit(1)
	}
	defer func() {
		for _, c := range certs {
			c.Close()
		}
	}()

	r.step("enumerate certificates", false, func() (string, error) {
		return fmt.Sprintf("%d certificates", len(certs)), nil
	})

	r.step("Store.Find FindByTimeValid", false, func() (string, error) {
		found, err := store.Find(gocades.FindByTimeValid, "", true)
		if err != nil {
			return "", err
		}
		defer func() {
			for _, c := range found {
				c.Close()
			}
		}()
		return fmt.Sprintf("%d valid", len(found)), nil
	})

	target, err := pickCertificate(certs, *thumb)
	if err != nil {
		if *thumb != "" {
			// A certificate was requested explicitly, so its absence is an error.
			fmt.Printf("  FAIL  %-42s %v\n", "select signer certificate", err)
			os.Exit(1)
		}
		r.noCert = true
		fmt.Printf("  INFO  %-42s %v\n", "no signer certificate", err)
	}

	var subject, thumbprint string
	if target != nil {
		subject, _ = target.SubjectName()
		thumbprint, _ = target.Thumbprint()
		fmt.Printf("  INFO  %-42s %s\n", "signer", subject)
		fmt.Printf("  INFO  %-42s %s\n", "thumbprint", thumbprint)

		if r.pin != "" {
			if err := target.SetPIN(r.pin); err != nil {
				fmt.Printf("  FAIL  %-42s %v\n", "set PIN", err)
				os.Exit(1)
			}
			fmt.Printf("  INFO  %-42s ok\n", "set PIN")
		}
		if r.prompt {
			fmt.Printf("  INFO  %-42s the CSP asks for the PIN in its window\n", "SMOKE_PIN_PROMPT")
		}
	}

	r.stepCert("Store.Find by thumbprint", false, func() (string, error) {
		tp, err := target.Thumbprint()
		if err != nil {
			return "", err
		}
		// Insert a separator so normalizeHex is exercised end-to-end.
		needle := tp[:4] + ":" + tp[4:]
		found, err := store.Find(gocades.FindBySHA1Hash, needle, true)
		if err != nil {
			return "", err
		}
		defer func() {
			for _, c := range found {
				c.Close()
			}
		}()
		if len(found) != 1 {
			return "", fmt.Errorf("want 1 match, got %d", len(found))
		}
		got, err := found[0].Thumbprint()
		if err != nil {
			return "", err
		}
		if !strings.EqualFold(got, tp) {
			return "", fmt.Errorf("thumbprint mismatch: got %s", got)
		}
		return got, nil
	})

	r.stepCert("Store.First by subject", false, func() (string, error) {
		subj, err := target.SubjectName()
		if err != nil {
			return "", err
		}
		first, err := store.First(gocades.FindBySubjectName, subj, true)
		if err != nil {
			return "", err
		}
		if first == nil {
			return "", fmt.Errorf("no match for subject")
		}
		defer first.Close()
		got, err := first.SubjectName()
		if err != nil {
			return "", err
		}
		return got, nil
	})

	r.stepCert("certificate fields", false, func() (string, error) {
		version, err := target.Version()
		if err != nil {
			return "", err
		}
		from, err := target.ValidFrom()
		if err != nil {
			return "", err
		}
		to, err := target.ValidTo()
		if err != nil {
			return "", err
		}
		serial, err := target.SerialNumber()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("v%d serial=%s valid %s..%s",
			version, serial,
			from.Format("2006-01-02"), to.Format("2006-01-02")), nil
	})

	r.stepCert("extensions and keys", false, func() (string, error) {
		ku, err := target.KeyUsage()
		if err != nil {
			return "", err
		}
		eku, err := target.ExtendedKeyUsage()
		if err != nil {
			return "", err
		}
		bc, err := target.BasicConstraints()
		if err != nil {
			return "", err
		}
		pub, err := target.PublicKey()
		if err != nil {
			return "", err
		}
		if r.verbose {
			fmt.Printf("        keyUsage bits=0x%02x present=%v\n", uint32(ku.Bits), ku.Present)
			fmt.Printf("        eku count=%d present=%v\n", eku.EKUs.Count(), eku.Present)
			fmt.Printf("        isCA=%v\n", bc.IsCertificateAuthority)
			fmt.Printf("        pubkey alg=%s bits=%d\n", pub.AlgorithmOID(), pub.Length())
		}
		return fmt.Sprintf("ku=%v eku=%d %d-bit key",
			ku.IsDigitalSignatureEnabled(), eku.EKUs.Count(), pub.Length()), nil
	})

	r.stepCert("private key container", false, func() (string, error) {
		pk, err := target.PrivateKey()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s / %s", pk.ProviderName, pk.ContainerName), nil
	})

	r.stepCert("PrivateKey.IsDefaultPin", false, func() (string, error) {
		pk, err := target.PrivateKey()
		if err != nil {
			return "", err
		}
		def, err := pk.IsDefaultPin()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("default PIN: %v", def), nil
	})

	section("Hashing")

	r.step("GOST R 34.11-2012 (256)", false, func() (string, error) {
		hd := gocades.NewHashedData()
		hd.SetAlgorithm(gocades.HashAlgGOST3411_2012_256)
		if err := hd.Hash([]byte("smoke test")); err != nil {
			return "", err
		}
		if got := len(hd.Value()); got != 32 {
			return "", fmt.Errorf("digest is %d bytes, want 32", got)
		}
		return fmt.Sprintf("%x", hd.Value()[:8]) + "…", nil
	})

	r.step("hash.Hash adapter matches", false, func() (string, error) {
		h := gocades.NewGOST3411_2012_256()
		h.Write([]byte("smoke "))
		h.Write([]byte("test"))
		viaAdapter := h.Sum(nil)

		hd := gocades.NewHashedData()
		hd.SetAlgorithm(gocades.HashAlgGOST3411_2012_256)
		if err := hd.Hash([]byte("smoke test")); err != nil {
			return "", err
		}
		if !bytes.Equal(viaAdapter, hd.Value()) {
			return "", fmt.Errorf("adapter and HashedData disagree")
		}
		if got := len(viaAdapter); got != 32 {
			return "", fmt.Errorf("digest is %d bytes, want 32", got)
		}
		return "incremental == one-shot", nil
	})

	r.step("HMAC GOST 2012-256 (RFC 7836)", false, func() (string, error) {
		hd := gocades.NewHashedData()
		hd.SetAlgorithm(gocades.HashAlgGOST3411_2012_256_HMAC)
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i)
		}
		hd.SetKey(key)
		if err := hd.Hash([]byte{0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21,
			0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00}); err != nil {
			return "", err
		}
		const want = "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
		if got := fmt.Sprintf("%x", hd.Value()); got != want {
			return "", fmt.Errorf("got %s, want %s", got, want)
		}
		return "matches the RFC test vector", nil
	})

	section("Signatures")

	var cms []byte

	r.stepCert("SignCades BES (detached)", true, func() (string, error) {
		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("smoke test payload"))

		out, err := sd.SignCades(target, gocades.CadesBES, true)
		if err != nil {
			return "", err
		}
		cms = out
		return fmt.Sprintf("%d bytes", len(out)), nil
	})

	r.stepCert("AuthenticatedAttributes at sign time", true, func() (string, error) {
		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("attr payload"))
		attr := gocades.Attribute{}
		attr.SetName(gocades.AttrDocumentName)
		attr.SetValueEncoding(gocades.EncodingBinary)
		if err := attr.SetValue("gocades-smoke"); err != nil {
			return "", err
		}
		sd.AuthenticatedAttributes().Add(attr)

		out, err := sd.SignCades(target, gocades.CadesBES, true)
		if err != nil {
			return "", err
		}
		infos, err := gocades.ParseCMSSignerInfos(out)
		if err != nil {
			return "", err
		}
		if len(infos) == 0 {
			return "", fmt.Errorf("no signer infos")
		}
		found, ok := infos[0].SignedAttributes.Find("1.3.6.1.4.1.311.88.2.1")
		if !ok {
			return "", fmt.Errorf("documentName attribute missing")
		}
		// ParseCMSSignerInfos returns the BMPString content octets (UTF-16BE).
		want := "gocades-smoke"
		got := found.Value()
		if len(got) != len(want)*2 {
			return "", fmt.Errorf("attribute value len=%d data=%x", len(got), got)
		}
		for i, r := range want {
			if got[i*2] != 0 || got[i*2+1] != byte(r) {
				return "", fmt.Errorf("attribute value %x", got)
			}
		}
		return "documentName present", nil
	})

	r.stepCert("VerifyCades BES", true, func() (string, error) {
		if cms == nil {
			return "", fmt.Errorf("no CMS from the previous step")
		}

		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("smoke test payload"))

		info, err := sd.VerifyCades(cms, gocades.CadesBES, true)
		if err != nil {
			return "", err
		}
		if !info.Valid {
			return "", fmt.Errorf("invalid: %s", gocades.VerifyStatusText(info.Status))
		}

		detail := "valid"
		if info.SignerCertificate != nil {
			subj, _ := info.SignerCertificate.SubjectName()
			if subj != subject {
				return "", fmt.Errorf("signer %q != %q", subj, subject)
			}
			detail = "valid, signer matched"
		}
		if sd.Signers().Count() != 1 {
			return "", fmt.Errorf("got %d signers, want 1", sd.Signers().Count())
		}
		if _, err := sd.Signers().Item(0); err != nil {
			return "", err
		}
		return detail, nil
	})

	r.stepCert("RawSignature sign/verify", true, func() (string, error) {
		hd := gocades.NewHashedData()
		hd.SetAlgorithm(gocades.HashAlgGOST3411_2012_256)
		if err := hd.Hash([]byte("raw")); err != nil {
			return "", err
		}

		rs := gocades.NewRawSignature()
		sig, err := rs.SignHash(target, hd)
		if err != nil {
			return "", err
		}
		if err := rs.VerifyHash(target, hd, sig); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d bytes", len(sig)), nil
	})

	// Two Certificate objects share one CryptoAPI context. Unlocking through one
	// and closing it must not release the provider still used by the other.
	r.stepCert("shared context: SetPIN, Close, sign", true, func() (string, error) {
		if r.prompt {
			return "", fmt.Errorf("%w: needs SMOKE_PIN for SetPIN", errSkipped)
		}
		again, err := store.Certificates()
		if err != nil {
			return "", err
		}
		twin, err := pickCertificate(again, thumbprint)
		if err != nil {
			return "", err
		}
		for i := 0; i < 2; i++ {
			if err := twin.SetPIN(r.pin); err != nil {
				return "", fmt.Errorf("SetPIN #%d: %w", i+1, err)
			}
		}
		for _, c := range again {
			c.Close()
		}
		if _, err := twin.Thumbprint(); !errors.Is(err, gocades.ErrClosed) {
			return "", fmt.Errorf("closed certificate: got %v, want ErrClosed", err)
		}
		runtime.GC()

		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("shared context"))
		out, err := sd.SignCades(target, gocades.CadesBES, true)
		if err != nil {
			return "", err
		}
		info, err := sd.VerifyCades(out, gocades.CadesBES, true)
		if err != nil {
			return "", err
		}
		if !info.Valid {
			return "", fmt.Errorf("invalid: %s", gocades.VerifyStatusText(info.Status))
		}
		return "provider survived the twin's Close", nil
	})

	r.stepCert("CoSignCades (second signer)", true, func() (string, error) {
		if cms == nil {
			return "", fmt.Errorf("no CMS from the previous step")
		}

		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("smoke test payload"))

		cosigned, err := sd.CoSignCades(target, cms, gocades.CadesBES)
		if err != nil {
			return "", err
		}

		info, err := sd.VerifyCades(cosigned, gocades.CadesBES, true)
		if err != nil {
			return "", err
		}
		if !info.Valid {
			return "", fmt.Errorf("invalid: %s", gocades.VerifyStatusText(info.Status))
		}
		if got := sd.Signers().Count(); got != 2 {
			return "", fmt.Errorf("got %d signers, want 2", got)
		}
		return fmt.Sprintf("%d bytes, 2 signers", len(cosigned)), nil
	})

	// Plain CMS goes through the CryptoAPI message layer and is verified with
	// CadesPKCS7; CadesDefault would demand CAdES-X Long Type 1 evidence.
	r.stepCert("Sign / CoSign / Verify (plain CMS)", true, func() (string, error) {
		der, err := target.ExportDER()
		if err != nil {
			return "", err
		}
		payload := []byte("plain CMS payload")
		for _, detached := range []bool{true, false} {
			sd := gocades.NewSignedData()
			defer sd.Close()
			sd.SetContent(payload)
			sig, err := sd.Sign(target, detached)
			if err != nil {
				return "", fmt.Errorf("Sign(detached=%v): %w", detached, err)
			}
			// Verifiers other than CryptoPro need the certificate in the CMS.
			if !bytes.Contains(sig, der) {
				return "", fmt.Errorf("Sign(detached=%v): signer certificate is not embedded", detached)
			}
			if !detached {
				// An attached signature carries its content.
				sd.SetContent(nil)
			}
			cosigned, err := sd.CoSign(target, sig)
			if err != nil {
				return "", fmt.Errorf("CoSign(detached=%v): %w", detached, err)
			}
			if detached {
				sd.SetContent(payload)
			}
			info, err := sd.Verify(cosigned, detached)
			info.Close()
			if err != nil {
				return "", fmt.Errorf("Verify(detached=%v): %w", detached, err)
			}
			if got := sd.Signers().Count(); got != 2 {
				return "", fmt.Errorf("detached=%v: got %d signers, want 2", detached, got)
			}
		}
		return "detached and attached, 2 valid signers each", nil
	})

	// GetMsgType checks signer 0 from the strongest type down, as
	// CPPCadesSignedDataObject::GetMsgType does.
	r.stepCert("GetMsgType / IsMsgType", true, func() (string, error) {
		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("message type payload"))
		bes, err := sd.SignCades(target, gocades.CadesBES, true)
		if err != nil {
			return "", err
		}
		plain, err := sd.Sign(target, true)
		if err != nil {
			return "", err
		}
		besType, err := sd.GetMsgType(bes)
		if err != nil {
			return "", fmt.Errorf("GetMsgType(BES): %w", err)
		}
		if besType != gocades.CadesBES {
			return "", fmt.Errorf("GetMsgType(BES) = %#x, want CadesBES", besType)
		}
		for _, c := range []struct {
			t    gocades.CadesType
			want bool
		}{{gocades.CadesBES, true}, {gocades.CadesT, false}, {gocades.CadesXLongType1, false}} {
			got, err := sd.IsMsgType(bes, c.t)
			if err != nil || got != c.want {
				return "", fmt.Errorf("IsMsgType(BES, %#x) = %v, %v; want %v", c.t, got, err, c.want)
			}
		}
		// CryptoPro's CryptSignMessage adds signingCertificateV2 on its own,
		// which is all CAdES-BES needs.
		plainType, err := sd.GetMsgType(plain)
		if err != nil {
			return "", fmt.Errorf("GetMsgType(plain CMS): %w", err)
		}
		if plainType != gocades.CadesBES {
			return "", fmt.Errorf("GetMsgType(plain CMS) = %#x, want CadesBES", plainType)
		}
		return "CAdES-BES and plain CMS both report CadesBES", nil
	})

	// Sign must use the digest set with SetHashAlgorithm: a 2012-512 digest
	// does not fit a 2012-256 key and has to be refused, not silently
	// replaced by 2012-256.
	r.stepCert("Sign honours SetHashAlgorithm", true, func() (string, error) {
		gost256 := []byte{0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02}

		pk, err := target.PublicKey()
		if err != nil {
			return "", err
		}
		if alg := pk.AlgorithmOID(); alg != "1.2.643.7.1.1.1.1" {
			return "skipped: needs a GOST R 34.10-2012 256 key, have " + alg, nil
		}

		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("hash algorithm payload"))
		sd.SetHashAlgorithm("1.2.643.7.1.1.2.2")
		sig, err := sd.Sign(target, true)
		if err != nil {
			return "", err
		}
		if !bytes.Contains(sig, gost256) {
			return "", fmt.Errorf("GOST R 34.11-2012 256 OID not found in the CMS")
		}

		sd.SetHashAlgorithm("1.2.643.7.1.1.2.3")
		if _, err := sd.Sign(target, true); err == nil {
			return "", fmt.Errorf("2012-512 digest with a 2012-256 key was not refused")
		}
		return "2012-256 used, 2012-512 refused for a 2012-256 key", nil
	})

	// An invalid signature must fail with a *VerifyError that carries the
	// status, and still return the signer information.
	r.stepCert("invalid signature: VerifyError with info", true, func() (string, error) {
		if cms == nil {
			return "", fmt.Errorf("no CMS from the previous step")
		}
		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("tampered payload"))

		info, err := sd.VerifyCades(cms, gocades.CadesBES, true)
		defer info.Close()
		var ve *gocades.VerifyError
		if !errors.As(err, &ve) {
			return "", fmt.Errorf("got %v, want *VerifyError", err)
		}
		if ve.Status != gocades.VerifyBadSignature || info.Status != ve.Status || info.Valid {
			return "", fmt.Errorf("status %d / info %d valid=%v, want %d",
				ve.Status, info.Status, info.Valid, gocades.VerifyBadSignature)
		}
		if info.SignerCertificate == nil {
			return "", fmt.Errorf("no signer certificate with the error")
		}
		if err := gocades.VerifyDetached(cms, []byte("tampered payload"), gocades.CadesBES); !errors.As(err, &ve) ||
			ve.Status != gocades.VerifyBadSignature {
			return "", fmt.Errorf("VerifyDetached: got %v, want bad signature", err)
		}
		return gocades.VerifyStatusText(ve.Status), nil
	})

	// Every signer is verified once; a bad second signer is reported and
	// kept in Signers instead of being dropped.
	r.stepCert("bad second signer is reported", true, func() (string, error) {
		if cms == nil {
			return "", fmt.Errorf("no CMS from the previous step")
		}
		other := gocades.NewSignedData()
		other.SetContent([]byte("some other payload"))
		mixed, err := other.CoSignCades(target, cms, gocades.CadesBES)
		if err != nil {
			return "", err
		}

		sd := gocades.NewSignedData()
		defer sd.Close()
		sd.SetContent([]byte("smoke test payload"))
		info, err := sd.VerifyCades(mixed, gocades.CadesBES, true)
		info.Close()
		var ve *gocades.VerifyError
		if !errors.As(err, &ve) || ve.Signer != 1 {
			return "", fmt.Errorf("got %v, want *VerifyError for signer 1", err)
		}
		signers := sd.Signers().All()
		if len(signers) != 2 {
			return "", fmt.Errorf("got %d signers, want 2", len(signers))
		}
		if !signers[0].SignatureStatus.IsValid || signers[1].SignatureStatus.IsValid ||
			signers[1].SignatureStatus.Err == nil || signers[1].Certificate == nil {
			return "", fmt.Errorf("signer statuses %+v / %+v", signers[0].SignatureStatus, signers[1].SignatureStatus)
		}

		// The same CMS with a BER indefinite outer length: a re-encoding
		// must not hide the bad signer.
		ber, err := indefiniteOuter(mixed)
		if err != nil {
			return "", err
		}
		info, err = sd.VerifyCades(ber, gocades.CadesBES, true)
		info.Close()
		if !errors.As(err, &ve) || ve.Signer != 1 || sd.Signers().Count() != 2 {
			return "", fmt.Errorf("BER re-encoding: got %v, %d signers; want signer 1 reported",
				err, sd.Signers().Count())
		}
		return "signer 1: " + gocades.VerifyStatusText(ve.Status) + ", also in BER", nil
	})

	detachedContent := []byte("detached payload")
	var detachedBES []byte

	r.stepCert("SignDetached / SignDetachedHash", true, func() (string, error) {
		sig, err := gocades.SignDetached(target, detachedContent, gocades.SignOptions{Type: gocades.CadesBES})
		if err != nil {
			return "", fmt.Errorf("SignDetached: %w", err)
		}
		if err := gocades.VerifyDetached(sig, detachedContent, gocades.CadesBES); err != nil {
			return "", fmt.Errorf("verify SignDetached: %w", err)
		}

		hd := gocades.NewHashedData()
		hd.SetAlgorithm(gocades.HashAlgGOST3411_2012_256)
		if err := hd.Hash(detachedContent); err != nil {
			return "", err
		}
		sigHash, err := gocades.SignDetachedHash(target, hd.Value(), gocades.SignOptions{Type: gocades.CadesBES})
		if err != nil {
			return "", fmt.Errorf("SignDetachedHash: %w", err)
		}
		if err := gocades.VerifyDetached(sigHash, detachedContent, gocades.CadesBES); err != nil {
			return "", fmt.Errorf("verify SignDetachedHash: %w", err)
		}

		detachedBES = sig
		return fmt.Sprintf("%d / %d bytes, both verify", len(sig), len(sigHash)), nil
	})

	r.stepCert("Options: certificates in the CMS", true, func() (string, error) {
		count := func(o gocades.CertIncludeOption) (int, error) {
			sd := gocades.NewSignedData()
			defer sd.Close()
			sd.SetContent([]byte("include options"))
			sd.SetOptions(o)
			out, err := sd.SignCades(target, gocades.CadesBES, true)
			if err != nil {
				return 0, err
			}
			certs, err := sd.Certificates()
			if err != nil {
				return 0, err
			}
			for _, c := range certs {
				c.Close()
			}

			check := gocades.NewSignedData()
			defer check.Close()
			check.SetContent([]byte("include options"))
			if _, err := check.VerifyCades(out, gocades.CadesBES, true); err != nil {
				return 0, fmt.Errorf("verify: %w", err)
			}
			again, err := check.Certificates()
			if err != nil {
				return 0, err
			}
			for _, c := range again {
				c.Close()
			}
			if len(again) != len(certs) {
				return 0, fmt.Errorf("signer sees %d certificates, verifier %d", len(certs), len(again))
			}
			return len(certs), nil
		}

		got := map[gocades.CertIncludeOption]int{}
		for _, o := range []gocades.CertIncludeOption{
			gocades.IncludeNone, gocades.IncludeEndEntityOnly,
			gocades.IncludeChainExceptRoot, gocades.IncludeWholeChain,
		} {
			n, err := count(o)
			if err != nil {
				return "", fmt.Errorf("option %#x: %w", int32(o), err)
			}
			got[o] = n
		}
		switch {
		case got[gocades.IncludeNone] != 0:
			return "", fmt.Errorf("IncludeNone embeds %d certificates", got[gocades.IncludeNone])
		case got[gocades.IncludeEndEntityOnly] != 1:
			return "", fmt.Errorf("IncludeEndEntityOnly embeds %d certificates", got[gocades.IncludeEndEntityOnly])
		case got[gocades.IncludeChainExceptRoot] < 1,
			got[gocades.IncludeWholeChain] < got[gocades.IncludeChainExceptRoot]:
			return "", fmt.Errorf("chain options embed %d (except root) and %d (whole chain)",
				got[gocades.IncludeChainExceptRoot], got[gocades.IncludeWholeChain])
		}
		return fmt.Sprintf("none=0 end-entity=1 except-root=%d whole=%d",
			got[gocades.IncludeChainExceptRoot], got[gocades.IncludeWholeChain]), nil
	})

	if r.tsa != "" {
		r.stepCert("Enhance BES to T", true, func() (string, error) {
			if detachedBES == nil {
				return "", fmt.Errorf("no detached BES from the previous step")
			}
			out, err := gocades.Enhance(detachedBES, gocades.CadesT, r.tsa)
			if err != nil {
				return "", err
			}
			if err := gocades.VerifyDetached(out, detachedContent, gocades.CadesT); err != nil {
				return "", fmt.Errorf("verify enhanced: %w", err)
			}
			return fmt.Sprintf("%d -> %d bytes", len(detachedBES), len(out)), nil
		})

		r.stepCert("SignCades T (timestamp)", true, func() (string, error) {
			sd := gocades.NewSignedData()
			defer sd.Close()
			sd.SetContent([]byte("smoke test payload"))
			sd.SetTSAAddress(r.tsa)

			out, err := sd.SignCades(target, gocades.CadesT, true)
			if err != nil {
				return "", err
			}
			info, err := sd.VerifyCades(out, gocades.CadesT, true)
			if err != nil {
				return "", err
			}
			if !info.Valid {
				return "", fmt.Errorf("invalid: %s", gocades.VerifyStatusText(info.Status))
			}
			return fmt.Sprintf("%d bytes, ts=%s", len(out),
				info.SignatureTimeStampTime.Format(time.RFC3339)), nil
		})
	}

	section("Enveloped data")

	r.stepCert("Encrypt for the signer certificate", false, func() (string, error) {
		ed := gocades.NewEnvelopedData()
		ed.SetContent([]byte("secret"))
		if err := ed.Recipients().Add(target); err != nil {
			return "", err
		}
		out, err := ed.Encrypt()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d bytes", len(out)), nil
	})

	r.stepCert("decrypt", true, func() (string, error) {
		ed := gocades.NewEnvelopedData()
		ed.SetContent([]byte("secret"))
		if err := ed.Recipients().Add(target); err != nil {
			return "", err
		}
		ct, err := ed.Encrypt()
		if err != nil {
			return "", err
		}

		ed.SetStore(store)
		pt, err := ed.Decrypt(ct)
		if err != nil {
			return "", err
		}
		if string(pt) != "secret" {
			return "", fmt.Errorf("round trip mismatch")
		}
		return "round trip ok", nil
	})

	section("Symmetric algorithm")

	r.step("generate / encrypt / decrypt", false, func() (string, error) {
		sym, err := gocades.NewSymmetricAlgorithm()
		if err != nil {
			return "", err
		}
		defer sym.Close()

		if err := sym.GenerateKey(gocades.EncryptionGOST28147); err != nil {
			return "", err
		}
		if err := sym.SetMode(gocades.ModeCBC); err != nil {
			return "", err
		}

		ct, err := sym.Encrypt([]byte("0123456789abcdef"))
		if err != nil {
			return "", err
		}

		if err := sym.SetIV(mustIV(sym)); err != nil {
			return "", err
		}
		pt, err := sym.Decrypt(ct)
		if err != nil {
			return "", err
		}
		if string(pt) != "0123456789abcdef" {
			return "", fmt.Errorf("round trip mismatch")
		}
		return fmt.Sprintf("%d -> %d bytes", len(ct), len(pt)), nil
	})

	r.stepCert("ExportKey (GOST)", false, func() (string, error) {
		sym, err := gocades.NewSymmetricAlgorithm()
		if err != nil {
			return "", err
		}
		defer sym.Close()
		if err := sym.GenerateKey(gocades.EncryptionGOST28147); err != nil {
			return "", err
		}
		blob, err := sym.ExportKey(target)
		if err != nil {
			return "", err
		}
		if len(blob) < 10 || blob[0] < '0' {
			return "", fmt.Errorf("unexpected transport blob")
		}
		return fmt.Sprintf("%d bytes", len(blob)), nil
	})

	r.stepCert("ImportKey roundtrip (GOST)", true, func() (string, error) {
		sym, err := gocades.NewSymmetricAlgorithm()
		if err != nil {
			return "", err
		}
		defer sym.Close()

		if err := sym.GenerateKey(gocades.EncryptionGOST28147); err != nil {
			return "", err
		}
		if err := sym.SetMode(gocades.ModeCBC); err != nil {
			return "", err
		}
		iv := mustIV(sym)
		pt := []byte("0123456789abcdef")
		ct, err := sym.Encrypt(pt)
		if err != nil {
			return "", err
		}
		blob, err := sym.ExportKey(target)
		if err != nil {
			return "", err
		}

		imp, err := gocades.NewSymmetricAlgorithm()
		if err != nil {
			return "", err
		}
		defer imp.Close()
		if err := imp.ImportKey(target, blob); err != nil {
			return "", err
		}
		if err := imp.SetMode(gocades.ModeCBC); err != nil {
			return "", err
		}
		if err := imp.SetIV(iv); err != nil {
			return "", err
		}
		got, err := imp.Decrypt(ct)
		if err != nil {
			return "", err
		}
		if string(got) != string(pt) {
			return "", fmt.Errorf("round trip mismatch")
		}
		return fmt.Sprintf("transport %d bytes", len(blob)), nil
	})

	section("XMLDSig")

	r.stepCert("Sign and Verify (XAdES-BES)", true, func() (string, error) {
		sx := gocades.NewSignedXML()
		sx.SetContent([]byte(smokeXML))
		sx.SetSignatureType(gocades.XAdESBES)
		sx.SetStore(store)

		signed, err := sx.Sign(target)
		if err != nil {
			return "", err
		}

		infos, err := sx.Verify(signed)
		if err != nil {
			return "", err
		}
		if len(infos) == 0 {
			return "", fmt.Errorf("no signatures found")
		}
		if !infos[0].Valid {
			return "", fmt.Errorf("invalid: %s", gocades.VerifyStatusText(infos[0].Status))
		}
		for _, in := range infos {
			if in.SignerCertificate == nil {
				return "", fmt.Errorf("no signer certificate")
			}
			// Use the certificate after the C-side result array was freed.
			if _, err := in.SignerCertificate.Thumbprint(); err != nil {
				return "", err
			}
			in.SignerCertificate.Close()
		}

		tampered := bytes.Replace(signed, []byte("smoke test<"), []byte("smoke TEST<"), 1)
		if bytes.Equal(tampered, signed) {
			return "", fmt.Errorf("could not tamper with the signed XML")
		}
		bad, err := sx.Verify(tampered)
		var ve *gocades.VerifyError
		if !errors.As(err, &ve) {
			return "", fmt.Errorf("tampered XML: got %v, want *VerifyError", err)
		}
		for _, in := range bad {
			in.SignerCertificate.Close()
		}
		return fmt.Sprintf("%d bytes, %s; tampered: %s", len(signed), infos[0].VerifiedXAdESType,
			gocades.VerifyStatusText(ve.Status)), nil
	})

	// SKIP_PADES=1: CI GHCR images omit poppler/fonts; PAdES is covered locally
	// via make verify-crypto (docker/local) and unit tests in internal/pdfsign.
	if os.Getenv("SKIP_PADES") == "1" {
		section("PAdES")
		r.skipped++
		fmt.Printf("  SKIP  %-42s set SKIP_PADES=0 (or unset) to enable\n", "PAdES section")
	} else {
		section("PAdES")

		r.step("Prepare with a GOST digest", false, func() (string, error) {
			prep, err := pdfsign.Prepare(smokePDF(), pdfsign.Options{
				Hash:    pdfsign.HashGOST3411_2012_256,
				NewHash: gocades.NewGOST3411_2012_256,
			})
			if err != nil {
				return "", err
			}
			if got := len(prep.Digest); got != 32 {
				return "", fmt.Errorf("digest is %d bytes, want 32", got)
			}
			return fmt.Sprintf("field=%s digest=%d bytes", prep.FieldName, len(prep.Digest)), nil
		})

		var (
			prepared      *pdfsign.Prepared
			signedCMS     []byte
			signedContent []byte
			signedPDF     []byte
			signedPath    string
			cosignedPath  string
		)
		defer func() {
			for _, p := range []string{signedPath, cosignedPath} {
				if p != "" {
					os.Remove(p)
				}
			}
		}()

		r.step("Prepare for signing", true, func() (string, error) {
			opts := pdfsign.Options{
				Hash:    pdfsign.HashGOST3411_2012_256,
				NewHash: gocades.NewGOST3411_2012_256,
				Reason:  "smoke test",
			}
			if font := pdfsign.SystemFont(); font != nil {
				opts.Stamp = &pdfsign.Stamp{Font: font}
				opts.SignerName = "gocades smoke test"
			}

			var err error
			prepared, err = pdfsign.Prepare(smokePDF(), opts)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%d bytes, stamp=%t", len(prepared.PDF), opts.Stamp != nil), nil
		})

		r.stepCert("sign the /ByteRange", true, func() (string, error) {
			if prepared == nil {
				return "", fmt.Errorf("no prepared document")
			}

			sd := gocades.NewSignedData()
			defer sd.Close()
			sd.SetContent(prepared.SignedContent())

			cmsOut, err := sd.SignCades(target, gocades.CadesBES, true)
			if err != nil {
				return "", err
			}

			signed, err := prepared.Assemble(cmsOut)
			if err != nil {
				return "", err
			}

			signedCMS, signedContent, signedPDF = cmsOut, prepared.SignedContent(), signed

			if signedPath, err = writeTemp(signed); err != nil {
				return "", err
			}
			return fmt.Sprintf("%d bytes cms, %d bytes pdf", len(cmsOut), len(signed)), nil
		})

		// pdfsign writes and re-reads PDFs with its own code, so its unit tests only
		// prove self-consistency. These checks hand the result to CryptoPro and to
		// poppler, which know nothing about this module.
		r.stepCert("verify CAdES over the signed range", true, func() (string, error) {
			if signedCMS == nil {
				return "", fmt.Errorf("no CMS from the previous step")
			}
			if err := gocades.VerifyDetached(signedCMS, signedContent, gocades.CadesBES); err != nil {
				return "", err
			}
			return "signature matches the /ByteRange bytes", nil
		})

		// A CMS without the signer certificate still verifies locally, because the
		// certificate is in the store. Every other verifier sees an empty
		// certificate list, so the certificate must be inside the CMS itself.
		r.stepCert("CMS embeds the signer certificate", true, func() (string, error) {
			if signedCMS == nil {
				return "", fmt.Errorf("no CMS from the previous step")
			}
			der, err := target.ExportDER()
			if err != nil {
				return "", err
			}
			if !bytes.Contains(signedCMS, der) {
				return "", fmt.Errorf("the CMS (%d bytes) does not contain the %d-byte signer certificate",
					len(signedCMS), len(der))
			}
			return fmt.Sprintf("%d-byte certificate inside a %d-byte CMS", len(der), len(signedCMS)), nil
		})

		// A second signature is an incremental update: the first revision, its
		// /ByteRange included, must stay byte for byte as it was signed.
		r.stepCert("second signature keeps the first", true, func() (string, error) {
			if signedPDF == nil {
				return "", fmt.Errorf("no signed document")
			}
			prep, err := pdfsign.Prepare(signedPDF, pdfsign.Options{
				Hash:    pdfsign.HashGOST3411_2012_256,
				NewHash: gocades.NewGOST3411_2012_256,
				Reason:  "Повторная подпись",
			})
			if err != nil {
				return "", err
			}
			if !bytes.HasPrefix(prep.PDF, signedPDF) {
				return "", fmt.Errorf("preparing the second signature changed the first revision")
			}

			sd := gocades.NewSignedData()
			defer sd.Close()
			sd.SetContent(prep.SignedContent())
			cms2, err := sd.SignCades(target, gocades.CadesBES, true)
			if err != nil {
				return "", err
			}
			both, err := prep.Assemble(cms2)
			if err != nil {
				return "", err
			}

			first, err := pdfsign.SignedContent(both, prepared.ByteRange)
			if err != nil {
				return "", err
			}
			if err := gocades.VerifyDetached(signedCMS, first, gocades.CadesBES); err != nil {
				return "", fmt.Errorf("first signature: %w", err)
			}
			if err := gocades.VerifyDetached(cms2, prep.SignedContent(), gocades.CadesBES); err != nil {
				return "", fmt.Errorf("second signature: %w", err)
			}

			if cosignedPath, err = writeTemp(both); err != nil {
				return "", err
			}
			return fmt.Sprintf("both verify, field=%s", prep.FieldName), nil
		})

		if pdfcheck.Available("pdfinfo") && pdfcheck.Available("pdfsig") {
			r.stepCert("pdfinfo parses the signed PDF", true, func() (string, error) {
				if signedPath == "" {
					return "", fmt.Errorf("no signed document")
				}
				return pdfcheck.Info(signedPath)
			})

			r.stepCert("pdfsig finds the signature", true, func() (string, error) {
				if signedPath == "" {
					return "", fmt.Errorf("no signed document")
				}
				return pdfcheck.Signatures(signedPath)
			})

			r.stepCert("pdfsig finds both signatures", true, func() (string, error) {
				if cosignedPath == "" {
					return "", fmt.Errorf("no twice-signed document")
				}
				n, err := pdfcheck.SignatureCount(cosignedPath)
				if err != nil {
					return "", err
				}
				if n != 2 {
					return "", fmt.Errorf("pdfsig sees %d signature(s), want 2", n)
				}
				return "2 signatures", nil
			})
		} else {
			fmt.Printf("  INFO  %-42s install poppler-utils to enable them\n",
				"independent PDF checks skipped")
		}
	} // SKIP_PADES

	section("PKCS #12")

	if pfxPath := os.Getenv("SMOKE_PFX"); pfxPath != "" {
		r.step("ImportPFX, sign with the imported key", false, func() (string, error) {
			return importPFX(pfxPath, os.Getenv("SMOKE_PFX_PASSWORD"))
		})
	} else {
		r.skipped++
		fmt.Printf("  SKIP  %-42s set SMOKE_PFX to enable\n", "ImportPFX, sign with the imported key")
	}

	/* ------------------------------------------------------------------ */

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("passed %d, failed %d, skipped %d, warnings %d\n",
		r.passed, r.failed, r.skipped, r.warned)

	if r.failed > 0 {
		os.Exit(1)
	}
}

// writeTemp stores data in a temporary PDF file and returns its path.
func writeTemp(data []byte) (string, error) {
	f, err := os.CreateTemp("", "gocades-smoke-*.pdf")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// importPFX imports a PFX file into a new store, signs with the imported key
// and verifies the signature; the certificate must chain to a trusted root.
func importPFX(path, password string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	wrong := gocades.NewStore()
	if err := wrong.ImportPFX(data, password+"-wrong", gocades.PFXNoPersistKey); err == nil {
		wrong.Close()
		return "", fmt.Errorf("a wrong password was accepted")
	}

	s := gocades.NewStore()
	defer s.Close()
	if err := s.ImportPFX(data, password, gocades.PFXNoPersistKey); err != nil {
		return "", err
	}
	certs, err := s.Certificates()
	if err != nil {
		return "", err
	}
	defer func() {
		for _, c := range certs {
			c.Close()
		}
	}()
	signer, err := pickCertificate(certs, "")
	if err != nil {
		return "", err
	}

	sd := gocades.NewSignedData()
	defer sd.Close()
	sd.SetContent([]byte("pfx"))
	out, err := sd.SignCades(signer, gocades.CadesBES, true)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	check := gocades.NewSignedData()
	defer check.Close()
	check.SetContent([]byte("pfx"))
	check.AdditionalStore(s)
	if _, err := check.VerifyCades(out, gocades.CadesBES, true); err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}
	subj, _ := signer.SubjectName()
	return fmt.Sprintf("%d certificate(s), signed as %s", len(certs), subj), nil
}

// pickCertificate selects the certificate to sign with.
func pickCertificate(certs []*gocades.Certificate, thumbprint string) (*gocades.Certificate, error) {
	if thumbprint != "" {
		want := normalizeHex(thumbprint)
		for _, c := range certs {
			got, err := c.Thumbprint()
			if err != nil {
				continue
			}
			if normalizeHex(got) == want {
				return c, nil
			}
		}
		return nil, fmt.Errorf("no certificate with thumbprint %s", thumbprint)
	}

	for _, c := range certs {
		if c.HasPrivateKey() {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no certificate with a private key in the store")
}

func normalizeHex(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(s))
}

func mustIV(s *gocades.SymmetricAlgorithm) []byte {
	iv, err := s.IV()
	if err != nil || len(iv) == 0 {
		return nil
	}
	return iv
}

const smokeXML = `<?xml version="1.0" encoding="UTF-8"?>
<document Id="smoke">
  <data>smoke test</data>
</document>`

// indefiniteOuter re-encodes the outer SEQUENCE of a DER CMS with the BER
// indefinite length.
func indefiniteOuter(der []byte) ([]byte, error) {
	if len(der) < 2 || der[0] != 0x30 {
		return nil, fmt.Errorf("not a DER SEQUENCE")
	}
	hdr := 2
	if der[1]&0x80 != 0 {
		hdr += int(der[1] & 0x7F)
	}
	if hdr > len(der) {
		return nil, fmt.Errorf("truncated DER header")
	}
	out := append([]byte{0x30, 0x80}, der[hdr:]...)
	return append(out, 0, 0), nil
}

// smokePDF builds a minimal one-page PDF with a classic cross-reference table.
func smokePDF() []byte {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
	}

	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")

	offsets := make([]int, len(objects))
	for i, o := range objects {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}

	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, xref)

	return b.Bytes()
}
