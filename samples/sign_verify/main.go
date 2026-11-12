// Аналог samples/sign_verify.py из pycades:
// CAdES-BES подпись и проверка.
//
//	GOCADES_PIN=... go run ./samples/sign_verify
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/vdryagunov/gocades"
	"github.com/vdryagunov/gocades/samples/internal/envcert"
)

func main() {
	if v, err := (gocades.About{}).CSPVersion(); err == nil {
		fmt.Printf("CryptoPro CSP %s\n", v.String())
	}

	store, cert, err := envcert.OpenSigner()
	if err != nil {
		fail(err)
	}
	defer store.Close()
	defer cert.Close()

	sd := gocades.NewSignedData()
	defer sd.Close()
	sd.SetContent([]byte("Test content to be signed"))
	sd.SetCheckCertificate(true)

	sig, err := sd.SignCades(cert, gocades.CadesBES, false)
	if err != nil {
		fail(err)
	}
	fmt.Println("--Signature--")
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
	fmt.Println("----")

	check := gocades.NewSignedData()
	defer check.Close()
	info, err := check.VerifyCades(sig, gocades.CadesBES, false)
	if err != nil {
		fail(err)
	}
	if info.SignerCertificate != nil {
		info.SignerCertificate.Close()
	}
	fmt.Println("Verified successfully")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
