package certutils

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Creator struct {
	caCrtPair         tls.Certificate
	caCrt             *x509.Certificate
	certfile, keyfile string
}

// NewCreator creates a new Creator that can be used to create new certificates signed by the CA in the Creator.
// The CA certificate and private key files must be in PEM format.
func NewCreator(caCertFile, caPvtKeyFile string) (*Creator, error) {
	var err error
	c := new(Creator)
	c.certfile = caCertFile
	c.keyfile = caPvtKeyFile
	if c.caCrtPair, err = tls.LoadX509KeyPair(caCertFile, caPvtKeyFile); err != nil {
		return nil, err
	}
	if c.caCrt, err = x509.ParseCertificate(c.caCrtPair.Certificate[0]); err != nil {
		return nil, err
	}
	return c, nil
}

// MakeNew will create a new certificate and key-pair and sign the certificate with the CA in a Creator.
// Required are the subject parameter, the age of the certificate, and the key size.
// SANs (Subject Alternative Names) are included in the certificate, and can be specified by the dnsNames parameter
// and or the IPs parameter.  The dnsNames parameter is a slice of strings that contains the DNS names
// that should be included in the certificate.  The IPs parameter is a slice of net.IP that contains the IP addresses
// that should be included in the certificate.  Usually one or both of these parameters are used to specify the
// Subject Alternative Names (SANs) for the certificate.  Using nil for both parameters will result in an empty SANs list.
func (c *Creator) MakeNew(subject pkix.Name, age time.Duration, keysize int, dnsNames []string, IPs []net.IP) (newcert, newkey []byte, err error) {
	var (
		serialNumber          *big.Int
		certBytes             []byte
		certpembuf, keypembuf bytes.Buffer
	)
	// Prepare certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	if serialNumber, err = rand.Int(rand.Reader, serialNumberLimit); err != nil {
		return
	}
	priv, _ := rsa.GenerateKey(rand.Reader, keysize)
	pub := &priv.PublicKey
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(age),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:     dnsNames,
		IPAddresses:  IPs,
	}
	if cert.SubjectKeyId, err = generateSubjectKeyID(pub); err != nil {
		return
	}

	// Sign the certificate
	certBytes, err = x509.CreateCertificate(rand.Reader, cert, c.caCrt, pub, c.caCrtPair.PrivateKey)
	if err != nil {
		return
	}

	// Encode cert and public key to PEM
	if err = pem.Encode(&certpembuf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err == nil {
		// Encode Private key to PEM
		err = pem.Encode(&keypembuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	}
	newcert = certpembuf.Bytes()
	newkey = keypembuf.Bytes()
	return
}

// SaveCert saves the certificate and private key to the specified path with the given basename.
// The certificate is saved as `basename.crt` and the private key as `basename.key`.
// Basename may contain a path, e.g. '/var/xxx/certificates/myCertificate', but then path should be empty, else
// path will be prepended to the path in basename.
// In all cases the resultant path must exist already.
func SaveCert(cert, key []byte, path string, basename string) error {
	if ext := filepath.Ext(basename); ext != "" {
		basename = basename[:len(basename)-len(ext)] // remove extension if any
	}
	err := os.WriteFile(filepath.Join(path, fmt.Sprintf("%s.crt", basename)), cert, os.ModePerm)
	if err == nil {
		err = os.WriteFile(filepath.Join(path, fmt.Sprintf("%s.key", basename)), key, os.ModePerm)
	}
	return err
}

// generateSubjectKeyID generates SubjectKeyId used in a Certificate.
// The ID is a 160-bit SHA-1 hash of the BIT STRING subjectPublicKey.
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
	type rsaPublicKey struct {
		N *big.Int
		E int
	}
	var (
		pubBytes []byte
		err      error
	)
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("only RSA public key is supported")
	}
	hash := sha1.Sum(pubBytes)
	return hash[:], nil
}
