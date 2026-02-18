package certutils

import (
	"certutils/diskcache"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
)

/*
Test rely on having a running Pebble server on localhost:14000.
Using the following commands to install and start Pebble:
	git clone https://github.com/letsencrypt/pebble/
	cd pebble
	go install ./cmd/pebble
	PEBBLE_VA_ALWAYS_VALID=1 pebble -config ./test/config/pebble-config.json
  cp ./test/config/pebble.minica.pem <path to project>/certutils/testdata/pebble.minica.pem
*/

var pebbleIsRunning bool

// TestMain will be executed before any other tests in this package.
func TestMain(m *testing.M) {
	var err error

	for attempt := 1; attempt <= 1; attempt++ {
		var resp *http.Response

		time.Sleep(1 * time.Second)
		// Make sure we can open 'https://localhost:14000/dir' by trying to connect to it.
		httpClient := &http.Client{
			Transport: &http.Transport{
				// Skip TLS verification for testing purposes
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 1 * time.Second,
		}
		resp, err = httpClient.Get("https://localhost:14000/dir")
		if err == nil && resp.StatusCode == http.StatusOK {
			log.Println("Pebble server is up and running.")
			pebbleIsRunning = true
			break
		} else {
			if resp != nil {
				log.Printf("Pebble server not ready yet, attempt %d: %d %s", attempt, resp.StatusCode, resp.Status)
			} else {
				log.Printf("Pebble server not ready yet, attempt %d: %v", attempt, err)
			}
		}
	}

	exitCode := m.Run()

	os.Exit(exitCode)
}

type mockRedisConn struct {
	store      map[string][]byte
	redis.Conn // embed for interface
}

func (m *mockRedisConn) Do(commandName string, args ...interface{}) (reply interface{}, err error) {
	switch commandName {
	case "GET":
		key := args[0].(string)
		val, ok := m.store[key]
		if !ok {
			return nil, redis.ErrNil
		}
		return val, nil
	case "SET":
		key := args[0].(string)
		val := args[1].([]byte)
		m.store[key] = val
		return "OK", nil
	}
	return nil, errors.New("unsupported command")
}

func Test_NoCache(t *testing.T) {
	if !pebbleIsRunning {
		t.Skip("Skipping test that requires a running Pebble server")
	}
	os.Setenv("LEGO_CA_CERTIFICATES", "./testdata/pebble.minica.pem")
	os.Setenv("ACME_RENEWAL_WINDOW", "10s")

	email := "test@example.com"
	domain := []string{"test.example.com"}
	ctxExiting, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := NewAcmeClient(ctxExiting, email, domain, WithCADirURL("https://localhost:14000/dir"))
	if err != nil {
		t.Fatalf("Failed to create client: %s", err)
	}
	_, err = c.GetCert(nil)
	if err == nil {
		t.Log("Got a cert as expected")
	} else {
		t.Errorf("Expected to obtain a cert, but got error: %s", err)
	}
	t.Log("Sleeping for 15 seconds to allow for cert renewal")
	time.Sleep(15 * time.Second)
	t.Log("Waking up after sleep")
	_, err = c.GetCert(nil)
	if err == nil {
		t.Log("Got cert as expected")
	} else {
		t.Errorf("Expected to obtain a cert, but got error: %s", err)
	}
}

func Test_DiskCache(t *testing.T) {
	if !pebbleIsRunning {
		t.Skip("Skipping test that requires a running Pebble server")
	}
	os.Setenv("LEGO_CA_CERTIFICATES", "./testdata/pebble.minica.pem")
	os.Setenv("ACME_RENEWAL_WINDOW", "10s")

	cache := &diskcache.DiskCertCache{
		Dir: "./testdata",
	}
	email := "test@example.com"
	domain := []string{"test.example.com"}
	ctxExiting, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := NewAcmeClient(ctxExiting, email, domain,
		WithCADirURL("https://localhost:14000/dir"),
		WithCache(cache),
		WithRenewalAge(time.Second*10),
		WithRenewalCheckDuration(time.Second*5))
	if err != nil {
		t.Fatalf("Failed to create client: %s", err)
	}
	_, err = c.GetCert(nil)
	if err == nil {
		t.Log("Got a cert as expected")
	} else {
		t.Errorf("Expected to obtain a cert, but got error: %s", err)
	}
	t.Log("Sleeping for 15 seconds to allow for cert renewal")
	time.Sleep(15 * time.Second)
	t.Log("Waking up after sleep")
	_, err = c.GetCert(nil)
	if err == nil {
		t.Log("Got cert as expected")
	} else {
		t.Errorf("Expected to obtain a cert, but got error: %s", err)
	}
}

func Test_getOrCreateLetsEncryptCert(t *testing.T) {
	if !pebbleIsRunning {
		t.Skip("Skipping test that requires a running Pebble server")
	}
	os.Setenv("LEGO_CA_CERTIFICATES", "./testdata/pebble.minica.pem")
	cache := &diskcache.DiskCertCache{
		Dir: "./testdata",
	}
	email := "test@example.com"
	domain := []string{"test.example.com"}
	ctxExiting, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := NewAcmeClient(ctxExiting, email, domain,
		WithCADirURL("https://localhost:14000/dir"), WithCache(cache))
	if err != nil {
		t.Fatalf("Failed to create client: %s", err)
	}
	cert, certBytes, keyBytes, err := c.getOrCreateLetsEncryptCert()
	if err == nil && len(cert.Certificate) == 0 {
		t.Errorf("Expected non-empty cert bytes")
	} else if err != nil {
		t.Errorf("Expected to retrieve cert from cache, but got error: %s", err)
	} else {
		t.Log("Successfully retrieved cert")
		t.Log(string(certBytes))
		t.Log(string(keyBytes))
	}
}

// GenerateTestCert generates a self-signed certificate and private key with the given expiry offset.
func GenerateTestCert(domains []string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domains[0],
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(validFor),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: domains,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, nil
}

func TestAcmeClient_WillExpireWithin(t *testing.T) {
	type args struct {
		d time.Duration
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"Test will expire", args{d: 24 * time.Hour}, true},
		{"Test will not expire", args{d: 22 * time.Hour}, false},
	}
	var err error
	c := initClient(context.Background(), "jdoe@acme.com", []string{"example.com"})
	c.certBytes, c.keyBytes, err = GenerateTestCert([]string{"example.com"}, 23*time.Hour)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err != nil {
				t.Fatalf("Failed to generate test cert: %s", err)
			}
			if got := c.WillExpireWithin(tt.args.d); got != tt.want {
				t.Errorf("WillExpireWithin() = %v, want %v", got, tt.want)
			}
		})
	}
}
