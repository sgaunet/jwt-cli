package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// executeCommand executes a Cobra command and captures stdout/stderr.
// This helper allows testing command execution without running the full CLI.
//
// Note: Since the actual commands use fmt.Println (which writes to os.Stdout)
// instead of cmd.OutOrStdout(), we need to temporarily redirect os.Stdout
// to capture the output.
//
//nolint:unused // Shared test helper used across multiple test files
func executeCommand(cmd *cobra.Command, args ...string) (string, error) {
	// Create a pipe to capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Also set the command output (for errors and usage)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)

	// Execute the command
	err := cmd.Execute()

	// Restore stdout
	_ = w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var capturedOutput bytes.Buffer
	_, _ = capturedOutput.ReadFrom(r)

	// Return captured output (from stdout) plus command output (from SetOut)
	if err != nil {
		return capturedOutput.String() + buf.String(), fmt.Errorf("command execution failed: %w", err)
	}
	return capturedOutput.String() + buf.String(), nil
}

// createTempFile creates a temporary file with given content.
// The file is created in t.TempDir() and will be automatically cleaned up.
//
//nolint:unused // Shared test helper used across multiple test files
func createTempFile(t *testing.T, content []byte) string {
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

// generateRSAKeyPair generates a test RSA key pair and returns file paths.
// Both private and public keys are written to temporary files in PEM format.
//
//nolint:unused // Shared test helper used across multiple test files
func generateRSAKeyPair(t *testing.T) (string, string) {
	t.Helper()
	return generateRSAKeyPairWithBits(t, testRSAKeySize)
}

// generateRSAKeyPairWithBits writes an RSA key pair of the requested modulus size,
// so tests can exercise --allow-weak-key with a deliberately weak key.
//
//nolint:unused // Shared test helper used across multiple test files
func generateRSAKeyPairWithBits(t *testing.T, bits int) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
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
		Type:  testPEMPublicKey,
		Bytes: publicKeyBytes,
	}
	publicKeyPEMBytes := pem.EncodeToMemory(publicKeyPEM)

	privateKeyPath := createTempFile(t, privateKeyBytes)
	publicKeyPath := createTempFile(t, publicKeyPEMBytes)
	return privateKeyPath, publicKeyPath
}

// generateECDSAKeyPair generates a test ECDSA key pair for the given curve.
// Both private and public keys are written to temporary files in PEM format.
//
//nolint:unused // Shared test helper used across multiple test files
func generateECDSAKeyPair(t *testing.T, curve elliptic.Curve) (string, string) {
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
		Type:  testPEMECPrivateKey,
		Bytes: privateKeyBytes,
	}
	privateKeyPEMBytes := pem.EncodeToMemory(privateKeyPEM)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyPEM := &pem.Block{
		Type:  testPEMPublicKey,
		Bytes: publicKeyBytes,
	}
	publicKeyPEMBytes := pem.EncodeToMemory(publicKeyPEM)

	privateKeyPath := createTempFile(t, privateKeyPEMBytes)
	publicKeyPath := createTempFile(t, publicKeyPEMBytes)
	return privateKeyPath, publicKeyPath
}

// createInvalidPEMFile creates a file with invalid PEM content for testing error handling.
//
//nolint:unused // Shared test helper used across multiple test files
func createInvalidPEMFile(t *testing.T) string {
	t.Helper()
	return createTempFile(t, []byte("invalid pem content"))
}

// createWrongTypePEMFile creates a PEM file with wrong type for testing error handling.
//
//nolint:unused // Shared test helper used across multiple test files
func createWrongTypePEMFile(t *testing.T, pemType string) string {
	t.Helper()
	block := &pem.Block{
		Type:  pemType,
		Bytes: []byte("some data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

// createMalformedRSAKeyFile creates a PEM file with malformed RSA key data.
//
//nolint:unused // Shared test helper used across multiple test files
func createMalformedRSAKeyFile(t *testing.T) string {
	t.Helper()
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("malformed rsa key data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

// createMalformedECKeyFile creates a PEM file with malformed EC key data.
//
//nolint:unused // Shared test helper used across multiple test files
func createMalformedECKeyFile(t *testing.T) string {
	t.Helper()
	block := &pem.Block{
		Type:  testPEMECPrivateKey,
		Bytes: []byte("malformed ec key data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

// getNonExistentPath returns a path that doesn't exist for testing file not found errors.
//
//nolint:unused // Shared test helper used across multiple test files
func getNonExistentPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "nonexistent.pem")
}

// Test constants used across multiple test files.
//
//nolint:unused // Shared test constants used across multiple test files
const (
	// testPEMPublicKey is the PEM block type for PKIX public keys.
	testPEMPublicKey = "PUBLIC KEY"

	// testPEMECPrivateKey is the PEM block type for SEC 1 EC private keys.
	testPEMECPrivateKey = "EC PRIVATE KEY"

	// testRSAKeySize is the RSA key size used for test key generation (2048 bits).
	testRSAKeySize = 2048
	// testWeakRSAKeySize is below the 2048-bit floor the RS commands enforce.
	testWeakRSAKeySize = 1024

	// validPayload is a valid JSON payload for testing JWT encoding/decoding.
	validPayload = `{"sub":"1234567890","name":"John Doe","iat":1516239022}`

	// invalidJSON is an invalid JSON string for testing error handling.
	invalidJSON = `{invalid json`

	// complexPayload is a complex nested JSON for testing edge cases.
	complexPayload = `{"user":{"id":123,"name":"Alice","roles":["admin","user"]},"meta":{"created":"2024-01-01","nested":{"deep":true}}}`

	// hs256Secret is a valid 32-byte secret for HS256 algorithm (exactly 32 bytes).
	hs256Secret = "12345678901234567890123456789012"

	// hs384Secret is a valid 48-byte secret for HS384 algorithm (exactly 48 bytes).
	hs384Secret = "123456789012345678901234567890123456789012345678"

	// hs512Secret is a valid 64-byte secret for HS512 algorithm (exactly 64 bytes).
	hs512Secret = "1234567890123456789012345678901234567890123456789012345678901234"

	// weakSecret is a secret that doesn't meet minimum length requirements.
	weakSecret = "short"
)

// generateEd25519KeyPair generates a test Ed25519 key pair for PASETO v2/v4
// public tokens and returns the private and public key file paths in PEM form.
//
//nolint:unused // Shared test helper used across multiple test files
func generateEd25519KeyPair(t *testing.T) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal Ed25519 private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal Ed25519 public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  testPEMPublicKey,
		Bytes: publicKeyBytes,
	})

	return createTempFile(t, privateKeyPEM), createTempFile(t, publicKeyPEM)
}

// generateP384KeyPair generates a test NIST P-384 key pair for PASETO v3 public
// tokens and returns the private and public key file paths in PEM form.
//
// The private key uses the SEC 1 "EC PRIVATE KEY" encoding, matching what
// "jwt-cli paseto genkeys v3" instructs users to generate.
//
//nolint:unused // Shared test helper used across multiple test files
func generateP384KeyPair(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate P-384 key: %v", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal P-384 private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  testPEMECPrivateKey,
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal P-384 public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  testPEMPublicKey,
		Bytes: publicKeyBytes,
	})

	return createTempFile(t, privateKeyPEM), createTempFile(t, publicKeyPEM)
}

// pasetoTestKey is a valid hex-encoded 32-byte symmetric key for local tokens.
//
//nolint:unused // Shared test helper used across multiple test files
const pasetoTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// captureStderr redirects os.Stderr for the duration of fn and returns whatever
// was written to it.
//
// output() writes human-readable errors straight to os.Stderr rather than to
// cmd.ErrOrStderr(), so this is the only way to assert on what a failing
// command actually shows the user.
//
//nolint:unused // Shared test helper used across multiple test files
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("Failed to close pipe: %v", err)
	}
	var captured bytes.Buffer
	if _, err := captured.ReadFrom(r); err != nil {
		t.Fatalf("Failed to read captured stderr: %v", err)
	}
	return captured.String()
}
