// Package envcert — общие шаги примеров: PIN из окружения и сертификат с ключом.
package envcert

import (
	"fmt"
	"os"

	"github.com/vdryagunov/gocades"
)

// Pin returns GOCADES_PIN, otherwise SMOKE_PIN or CRYPTOPRO_PIN.
func Pin() string {
	for _, k := range []string{"GOCADES_PIN", "SMOKE_PIN", "CRYPTOPRO_PIN"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// OpenSigner opens CurrentUser/My and returns the first certificate that has a
// private key. If Pin() is set, it is applied with SetPIN. The caller must
// Close both the store and the certificate.
func OpenSigner() (*gocades.Store, *gocades.Certificate, error) {
	st, err := gocades.OpenStore(gocades.StoreCurrentUser, "My")
	if err != nil {
		return nil, nil, err
	}
	certs, err := st.Certificates()
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	var signer *gocades.Certificate
	for _, c := range certs {
		if signer == nil && c.HasPrivateKey() {
			signer = c
			continue
		}
		c.Close()
	}
	if signer == nil {
		st.Close()
		return nil, nil, fmt.Errorf("нет сертификата с закрытым ключом в CurrentUser/My")
	}
	if pin := Pin(); pin != "" {
		if err := signer.SetPIN(pin); err != nil {
			signer.Close()
			st.Close()
			return nil, nil, fmt.Errorf("SetPIN: %w", err)
		}
	}
	return st, signer, nil
}
