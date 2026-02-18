package diskcache

import (
	"errors"
	"os"
	"path/filepath"
)

type DiskCertCache struct {
	Dir string
}

// GetCertificate retrieves a certificate and key from disk.
// If the certificate or key file does not exist, it returns (nil, nil, error).
// The key parameter is used as a prefix for the filenames and must be a valid filename
// (only contains alphanumeric characters, dots, underscores, and hyphens).
func (d *DiskCertCache) GetCertificate(key string) ([]byte, []byte, error) {
	var (
		err       error
		certBytes []byte
		keyBytes  []byte
	)
	path := filepath.Join(d.Dir, key+"_cert.pem")
	if certBytes, err = os.ReadFile(path); err != nil {
		return nil, nil, err
	}
	path = filepath.Join(d.Dir, key+"_key.pem")
	if keyBytes, err = os.ReadFile(path); err != nil {
		return nil, nil, err
	}
	return certBytes, keyBytes, nil
}

// SetCertificate saves the certificate and key to disk with appropriate permissions.
// The key is the cache-key not any key having to do with the certificate itself.
// The cert and keyBytes are the PEM-encoded certificate and private key respectively.
func (d *DiskCertCache) SetCertificate(key string, cert []byte, keyBytes []byte) error {
	// create directory if it doesn't exist
	if err := os.MkdirAll(d.Dir, 0700); err != nil {
		return err
	}
	key = filepath.Clean(key)

	certPath := filepath.Join(d.Dir, key+"_cert.pem")
	keyPath := filepath.Join(d.Dir, key+"_key.pem")
	err := os.WriteFile(certPath, cert, 0600)
	if err != nil {
		return err
	}
	err = os.WriteFile(keyPath, keyBytes, 0600)
	if err != nil {
		_ = os.Remove(certPath) // Clean up the cert file if key write fails
		return err
	}
	return nil
}

// GetUser retrieves a LegoUser from disk. If the user file does not exist, it returns (nil, nil).
func (d *DiskCertCache) GetUserJSON(key string) ([]byte, error) {
	path := filepath.Join(d.Dir, key+"_user.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}

func (d *DiskCertCache) SetUserJSON(key string, data []byte) error {
	// create directory if it doesn't exist
	if err := os.MkdirAll(d.Dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(d.Dir, key+"_user.json")
	return os.WriteFile(path, data, 0600)
}
