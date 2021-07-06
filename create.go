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
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Creator struct {
	caCrtPair         tls.Certificate
	caCrt             *x509.Certificate
	certfile, keyfile string
}

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

// MakeNew will create a new certificate and key-pair and sign the certificate with the CA in a Creator
// Values must be supplied for keyusage and extkeyusage.  For example:
// keyusage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
// extkeyusage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
func (c *Creator) MakeNew(subject pkix.Name, age time.Duration, keysize int, keyusage x509.KeyUsage,
	extkeyusage []x509.ExtKeyUsage) (newcert, newkey []byte, err error) {
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
		ExtKeyUsage:  extkeyusage,
		KeyUsage:     keyusage,
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

func LoadCert(path string, basename string) (cert, key []byte, err error) {
	cert, err = ioutil.ReadFile(filepath.Join(path, fmt.Sprintf("%s.crt", basename)))
	if err == nil {
		key, err = ioutil.ReadFile(filepath.Join(path, fmt.Sprintf("%s.key", basename)))
	}
	return
}

func SaveCert(cert, key []byte, path string, basename string) error {
	err := ioutil.WriteFile(filepath.Join(path, fmt.Sprintf("%s.crt", basename)), cert, os.ModePerm)
	if err == nil {
		err = ioutil.WriteFile(filepath.Join(path, fmt.Sprintf("%s.key", basename)), key, os.ModePerm)
	}
	return err
}

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// Id is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
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
