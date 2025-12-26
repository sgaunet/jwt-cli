package cmd

import (
	"bytes"
	"crypto/ecdsa"
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
func executeCommand(cmd *cobra.Command, args ...string) (output string, err error) {
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
	err = cmd.Execute()

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

// registerEncodeFlags registers all encoding-related flags on a command.
// This mimics the flag registration done in root.go for encode commands.
func registerEncodeFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("payload", "p", "", "JSON payload")
	cmd.Flags().StringP("secret", "s", "", "HMAC secret")
	cmd.Flags().String("private-key", "", "path to RSA/ECDSA private key file")
	cmd.Flags().Bool("allow-weak-secret", false, "allow weak secrets")
	// Deprecated flags for backward compatibility
	cmd.Flags().String("p", "", "")
	_ = cmd.Flags().MarkDeprecated("p", "use --payload or -p instead")
	cmd.Flags().String("s", "", "")
	_ = cmd.Flags().MarkDeprecated("s", "use --secret or -s instead")
	cmd.Flags().String("pk", "", "")
	_ = cmd.Flags().MarkDeprecated("pk", "use --private-key instead")
}

// registerDecodeFlags registers all decoding-related flags on a command.
// This mimics the flag registration done in root.go for decode commands.
func registerDecodeFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("token", "t", "", "JWT token to decode")
	cmd.Flags().StringP("secret", "s", "", "HMAC secret")
	cmd.Flags().String("private-key", "", "path to RSA/ECDSA private key file")
	cmd.Flags().String("public-key", "", "path to RSA/ECDSA public key file")
	cmd.Flags().Bool("allow-weak-secret", false, "allow weak secrets")
	// Deprecated flags for backward compatibility
	cmd.Flags().String("t", "", "")
	_ = cmd.Flags().MarkDeprecated("t", "use --token or -t instead")
	cmd.Flags().String("s", "", "")
	_ = cmd.Flags().MarkDeprecated("s", "use --secret or -s instead")
	cmd.Flags().String("pk", "", "")
	_ = cmd.Flags().MarkDeprecated("pk", "use --private-key instead")
	cmd.Flags().String("pubk", "", "")
	_ = cmd.Flags().MarkDeprecated("pubk", "use --public-key instead")
}

// createTempFile creates a temporary file with given content.
// The file is created in t.TempDir() and will be automatically cleaned up.
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
func generateRSAKeyPair(t *testing.T) (privateKeyPath, publicKeyPath string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, testRSAKeySize)
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

// generateECDSAKeyPair generates a test ECDSA key pair for the given curve.
// Both private and public keys are written to temporary files in PEM format.
func generateECDSAKeyPair(t *testing.T, curve elliptic.Curve) (privateKeyPath, publicKeyPath string) {
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

// createInvalidPEMFile creates a file with invalid PEM content for testing error handling.
func createInvalidPEMFile(t *testing.T) string {
	t.Helper()
	return createTempFile(t, []byte("invalid pem content"))
}

// createWrongTypePEMFile creates a PEM file with wrong type for testing error handling.
func createWrongTypePEMFile(t *testing.T, pemType string) string {
	t.Helper()
	block := &pem.Block{
		Type:  pemType,
		Bytes: []byte("some data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

// createMalformedRSAKeyFile creates a PEM file with malformed RSA key data.
func createMalformedRSAKeyFile(t *testing.T) string {
	t.Helper()
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("malformed rsa key data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

// createMalformedECKeyFile creates a PEM file with malformed EC key data.
func createMalformedECKeyFile(t *testing.T) string {
	t.Helper()
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("malformed ec key data"),
	}
	return createTempFile(t, pem.EncodeToMemory(block))
}

// getNonExistentPath returns a path that doesn't exist for testing file not found errors.
func getNonExistentPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "nonexistent.pem")
}

// Test constants used across multiple test files.
const (
	// testRSAKeySize is the RSA key size used for test key generation (2048 bits).
	testRSAKeySize = 2048

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
