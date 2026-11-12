// Аналог samples/encrypt_decrypt.py из pycades:
// CMS EnvelopedData — шифрование и расшифрование.
//
//	GOCADES_PIN=... go run ./samples/encrypt_decrypt
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

	plain := []byte("Message to encrypt с русскими буквами")

	ed := gocades.NewEnvelopedData()
	ed.SetContent(plain)
	if err := ed.Recipients().Add(cert); err != nil {
		fail(err)
	}
	encrypted, err := ed.Encrypt()
	if err != nil {
		fail(err)
	}
	fmt.Println("--Encrypted Message--")
	fmt.Println(base64.StdEncoding.EncodeToString(encrypted))
	fmt.Println("----")

	ed2 := gocades.NewEnvelopedData()
	ed2.SetStore(store)
	out, err := ed2.Decrypt(encrypted)
	if err != nil {
		fail(err)
	}
	if string(out) != string(plain) {
		fail(fmt.Errorf("неверное содержимое после Decrypt: %q", out))
	}
	fmt.Println("Decrypted successfully")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
