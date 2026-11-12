// Аналог samples/enum_containers.py из pycades:
// перечисление контейнеров CSP и сведений о ключах.
//
//	go run ./samples/enum_containers
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"
	"unicode/utf8"

	"github.com/vdryagunov/gocades"
)

func main() {
	name, err := (gocades.About{}).CSPName(gocades.ProvGOST2012_256)
	if err != nil {
		fail(err)
	}
	csp, err := gocades.NewEnrollCspInformationFromName(name)
	if err != nil {
		fail(err)
	}
	conts, err := csp.EnumContainers()
	if err != nil {
		fail(err)
	}

	fmt.Printf("Containers: %d\n", conts.Count())
	for i := 0; i < conts.Count(); i++ {
		cont, err := conts.ItemByIndex(i)
		if err != nil {
			fail(err)
		}
		fmt.Printf("  #%d.\n", i+1)
		fmt.Printf("    Unique: %s\n", cont.UniqueName())
		fmt.Printf("    Name: %s\n", cont.Name())
		fmt.Printf("    Reader: %s\n", cont.Reader())
		fmt.Printf("    Media: %s\n", cont.Media())
		fmt.Printf("    FQCN: %s\n", cont.FQCN())

		keys, err := cont.Keys()
		if err != nil {
			fmt.Printf("    Keys: error: %v\n", err)
			continue
		}
		fmt.Printf("    Keys: %d\n", keys.Count())
		for j := 0; j < keys.Count(); j++ {
			key, err := keys.ItemByIndex(j)
			if err != nil {
				fail(err)
			}
			fmt.Printf("      %d.\n", j+1)
			fmt.Printf("        Exportable: %v\n", key.IsExportable())
			if exp := key.ExpirationTime(); !exp.IsZero() {
				fmt.Printf("        ExpirationTime: %s\n", exp.UTC().Format(time.RFC3339))
			}
			if pub := key.PublicKey(); pub != nil {
				if alg := pub.Algorithm(); alg != nil {
					fmt.Printf("        PublicKey Algorithm: %s\n", alg.Value)
					fmt.Printf("        PublicKey KeyLength: %d\n", pub.Length())
					_ = alg.FriendlyName()
				}
			}
			if fp := key.KP_FP(); fp != "" {
				if utf8.ValidString(fp) {
					fmt.Printf("        KP_FP: %s\n", fp)
				} else {
					fmt.Printf("        KP_FP: %s\n", hex.EncodeToString([]byte(fp)))
				}
			}
			if id := key.KP_ALGID(); id != 0 {
				fmt.Printf("        KP_ALGID: %d\n", id)
			}
			fmt.Printf("        HasCertificate: %v\n", key.HasCertificate())
			if key.HasCertificate() {
				c := key.Certificate()
				if c == nil {
					continue
				}
				subj, _ := c.SubjectName()
				iss, _ := c.IssuerName()
				ser, _ := c.SerialNumber()
				from, _ := c.ValidFrom()
				to, _ := c.ValidTo()
				tp, _ := c.Thumbprint()
				fmt.Printf("        Subject: %s\n", subj)
				fmt.Printf("        Issuer: %s\n", iss)
				fmt.Printf("        Serial: %s\n", ser)
				fmt.Printf("        Valid From: %s UTC\n", from.UTC().Format(time.RFC3339))
				fmt.Printf("        Valid To: %s UTC\n", to.UTC().Format(time.RFC3339))
				fmt.Printf("        Thumbprint: %s\n", tp)
				if pub, err := c.PublicKey(); err == nil && pub != nil {
					if alg := pub.Algorithm(); alg != nil {
						fmt.Printf("        Key Algorithm: %s\n", alg.FriendlyName())
					}
					fmt.Printf("        Key Length: %d\n", pub.Length())
				}
			}
		}
		keys.Close()
		fmt.Println()
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
