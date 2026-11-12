// Аналог samples/signhash_verifyhash.py из pycades:
// подпись и проверка заранее посчитанного хеша (CAdES-BES).
//
//	GOCADES_PIN=... go run ./samples/signhash_verifyhash
package main

import (
	"encoding/base64"
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

	hd := gocades.NewHashedData()
	hd.SetAlgorithm(gocades.HashAlgGOST3411_2012_256)
	if err := hd.Hash([]byte("test data")); err != nil {
		fail(err)
	}

	sd := gocades.NewSignedData()
	defer sd.Close()
	sd.SetCheckCertificate(true)

	sig, err := sd.SignHash(cert, hd.Value(), gocades.CadesBES)
	if err != nil {
		fail(err)
	}
	fmt.Println("--Signature--")
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
	fmt.Println("----")

	check := gocades.NewSignedData()
	defer check.Close()
	info, err := check.VerifyHash(sig, hd.Value(), gocades.CadesBES)
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
