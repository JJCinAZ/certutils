package diskcache

import (
	"testing"
)

func TestDiskCertCache_SetAndGetCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	cache := &DiskCertCache{Dir: tmpDir}

	key := "testdomain.com"
	certData := []byte("dummy-cert-pem")
	keyData := []byte("dummy-key-pem")

	// Test SetCertificate
	if err := cache.SetCertificate(key, certData, keyData); err != nil {
		t.Fatalf("SetCertificate failed: %v", err)
	}

	// Test GetCertificate
	gotCert, gotKey, err := cache.GetCertificate(key)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if string(gotCert) != string(certData) {
		t.Errorf("Cert mismatch: got %q, want %q", gotCert, certData)
	}
	if string(gotKey) != string(keyData) {
		t.Errorf("Key mismatch: got %q, want %q", gotKey, keyData)
	}
}
