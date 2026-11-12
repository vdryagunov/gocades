//go:build (!linux && !darwin) || !cgo

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr,
		"cmd/pdfsign: requires linux or darwin with CGO_ENABLED=1 and CryptoPro installed")
	os.Exit(1)
}
