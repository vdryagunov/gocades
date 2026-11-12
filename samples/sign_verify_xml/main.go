// Аналог samples/sign_verify_xml.py из pycades:
// XAdES-BES (enveloped) подпись XML и проверка.
//
//	GOCADES_PIN=... go run ./samples/sign_verify_xml
package main

import (
	"fmt"
	"os"

	"github.com/vdryagunov/gocades"
	"github.com/vdryagunov/gocades/samples/internal/envcert"
)

func main() {
	store, cert, err := envcert.OpenSigner()
	if err != nil {
		fail(err)
	}
	defer store.Close()
	defer cert.Close()

	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<root>
  <node>Hello, World!</node>
  <node>Hello, Node!</node>
</root>
`)

	sx := gocades.NewSignedXML()
	sx.SetContent(content)
	sx.SetSignatureType(gocades.XAdESBES)

	signed, err := sx.Sign(cert)
	if err != nil {
		fail(err)
	}
	fmt.Println("--Signature--")
	fmt.Println(string(signed))
	fmt.Println("----")

	check := gocades.NewSignedXML()
	check.SetStore(store)
	infos, err := check.Verify(signed)
	if err != nil {
		fail(err)
	}
	for _, info := range infos {
		if info.SignerCertificate != nil {
			info.SignerCertificate.Close()
		}
	}
	fmt.Println("Verified successfully")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
