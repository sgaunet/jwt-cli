package cryptojwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func createTempFile(t testing.TB, content []byte) string {
	t.Helper()
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}
	return tmpFile.Name()
}

func generateRSAKeyPair(t testing.TB) (privateKeyPath, publicKeyPath string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPEMBytes := pem.EncodeToMemory(publicKeyPEM)

	privateKeyPath = createTempFile(t, privateKeyBytes)
	publicKeyPath = createTempFile(t, publicKeyPEMBytes)
	return privateKeyPath, publicKeyPath
}

func generateECDSAKeyPair(t testing.TB, curve elliptic.Curve) (privateKeyPath, publicKeyPath string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal EC private key: %v", err)
	}
	privateKeyPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPEMBytes := pem.EncodeToMemory(privateKeyPEM)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPEMBytes := pem.EncodeToMemory(publicKeyPEM)

	privateKeyPath = createTempFile(t, privateKeyPEMBytes)
	publicKeyPath = createTempFile(t, publicKeyPEMBytes)
	return privateKeyPath, publicKeyPath
}

func createInvalidPEMFile(t testing.TB) string {
	t.Helper()
	return createTempFile(t, []byte("invalid pem content"))
}

func createWrongTypePEMFile(t testing.TB, pemType string) string {
	t.Helper()
	block := &pem.Block{
		Type:  pemType,
		Bytes: []byte("some data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

func createMalformedECKeyFile(t testing.TB) string {
	t.Helper()
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("malformed ec key data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

func createMalformedRSAKeyFile(t testing.TB) string {
	t.Helper()
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("malformed rsa key data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

func getNonExistentPath(t testing.TB) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "non-existent-file.pem")
}

const (
	validPayload = `{"sub":"1234567890","name":"John Doe","iat":1516239022}`
	invalidJSON  = `{invalid json}`
)