package certutils

import (
	"crypto/x509"
	"fmt"
	"os"
)

// NewCAPool can be used to create a CertPool from a CA certificate file in PEM format.  The file may
// contain multiple certificates, and they will all be added to the pool.
// It can be used to verify the certificate of a server or client in a TLS connection.
// For example:
//
//		  myConfig = &tls.Config{
//		     RootCAs: nil,
//		  }
//	   myConfig.RootCAs, err = certutils.NewCAPool("path/certfile.crt")
//
// Now the myConfig TLS configuration can be used to create a TLS connection to a server where the CA pool is
// used to verify the server's certificate.  This is useful when you want to connect to a server that uses a
// certificate signed by a private CA.
func NewCAPool(caCertFile string) (*x509.CertPool, error) {
	var (
		err  error
		data []byte
	)
	data, err = os.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to append certificate")
	}
	return p, nil
}
