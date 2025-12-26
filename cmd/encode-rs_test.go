package cmd

import (
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// TestRSEncodeCommand_Success tests successful JWT encoding for all RS algorithms
func TestRSEncodeCommand_Success(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		constructor func(string) cryptojwt.Encoder
	}{
		{
			name:        "RS256 valid encoding",
			algorithm:   "rs256",
			constructor: cryptojwt.NewRS256Encoder,
		},
		{
			name:        "RS384 valid encoding",
			algorithm:   "rs384",
			constructor: cryptojwt.NewRS384Encoder,
		},
		{
			name:        "RS512 valid encoding",
			algorithm:   "rs512",
			constructor: cryptojwt.NewRS512Encoder,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, _ := generateRSAKeyPair(t)

			cmd := createRSEncodeCommand(
				strings.ToUpper(tt.algorithm),
				tt.algorithm,
				"Test command",
				"Test description",
				"Test example",
				tt.constructor,
			)
			registerEncodeFlags(cmd)

			output, err := executeCommand(cmd,
				"--payload", validPayload,
				"--private-key", privateKey,
			)

			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			token := strings.TrimSpace(output)
			if token == "" {
				t.Fatal("Expected token output, got empty string")
			}

			// Verify JWT structure (header.payload.signature)
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("Expected JWT with 3 parts, got %d parts", len(parts))
			}
		})
	}
}

// TestRSEncodeCommand_ComplexPayload tests encoding with complex nested JSON
func TestRSEncodeCommand_ComplexPayload(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	output, err := executeCommand(cmd,
		"--payload", complexPayload,
		"--private-key", privateKey,
	)

	if err != nil {
		t.Fatalf("Expected no error with complex payload, got: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with complex payload")
	}
}

// TestRSEncodeCommand_MissingPrivateKey tests error when private-key flag is missing
func TestRSEncodeCommand_MissingPrivateKey(t *testing.T) {
	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", validPayload,
		// Missing --private-key flag
	)

	if err == nil {
		t.Fatal("Expected error for missing private key, got nil")
	}

	if !strings.Contains(err.Error(), "private key file is mandatory") {
		t.Errorf("Expected 'private key file is mandatory' error, got: %v", err)
	}
}

// TestRSEncodeCommand_MissingPayload tests error when payload flag is missing
func TestRSEncodeCommand_MissingPayload(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--private-key", privateKey,
		// Missing --payload flag
	)

	if err == nil {
		t.Fatal("Expected error for missing payload, got nil")
	}

	if !strings.Contains(err.Error(), "payload is mandatory") {
		t.Errorf("Expected 'payload is mandatory' error, got: %v", err)
	}
}

// TestRSEncodeCommand_InvalidJSON tests error handling for invalid JSON payload
func TestRSEncodeCommand_InvalidJSON(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", invalidJSON,
		"--private-key", privateKey,
	)

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}

	// The error should indicate encoding failure
	if !strings.Contains(err.Error(), "encoding failed") {
		t.Logf("Expected encoding error, got: %v", err)
	}
}

// TestRSEncodeCommand_NonExistentKeyFile tests error when key file doesn't exist
func TestRSEncodeCommand_NonExistentKeyFile(t *testing.T) {
	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	nonExistentPath := getNonExistentPath(t)

	_, err := executeCommand(cmd,
		"--payload", validPayload,
		"--private-key", nonExistentPath,
	)

	if err == nil {
		t.Fatal("Expected error for nonexistent key file, got nil")
	}

	if !strings.Contains(err.Error(), "encoding failed") {
		t.Logf("Expected file error, got: %v", err)
	}
}

// TestRSEncodeCommand_InvalidPEMFile tests error for invalid PEM content
func TestRSEncodeCommand_InvalidPEMFile(t *testing.T) {
	invalidPEM := createInvalidPEMFile(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", validPayload,
		"--private-key", invalidPEM,
	)

	if err == nil {
		t.Fatal("Expected error for invalid PEM, got nil")
	}

	if !strings.Contains(err.Error(), "encoding failed") {
		t.Logf("Expected PEM error, got: %v", err)
	}
}

// TestRSEncodeCommand_WrongKeyType tests error when using EC key instead of RSA
func TestRSEncodeCommand_WrongKeyType(t *testing.T) {
	// Generate an ECDSA key pair instead of RSA
	privateKey, _ := generateECDSAKeyPair(t, elliptic.P256())

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", validPayload,
		"--private-key", privateKey,
	)

	if err == nil {
		t.Fatal("Expected error for wrong key type, got nil")
	}

	if !strings.Contains(err.Error(), "encoding failed") {
		t.Logf("Expected key type error, got: %v", err)
	}
}

// TestRSEncodeCommand_MalformedKey tests error for malformed RSA key
func TestRSEncodeCommand_MalformedKey(t *testing.T) {
	malformedKey := createMalformedRSAKeyFile(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", validPayload,
		"--private-key", malformedKey,
	)

	if err == nil {
		t.Fatal("Expected error for malformed key, got nil")
	}

	if !strings.Contains(err.Error(), "encoding failed") {
		t.Logf("Expected parse error, got: %v", err)
	}
}

// TestRSEncodeCommand_DeprecatedPrivateKeyFlag tests deprecated --pk flag
// Note: This test can be removed when deprecated flags are removed from the CLI
func TestRSEncodeCommand_DeprecatedPrivateKeyFlag(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	// Test deprecated --pk flag
	output, err := executeCommand(cmd,
		"--payload", validPayload,
		"--pk", privateKey,
	)

	if err != nil {
		t.Fatalf("Expected deprecated --pk flag to work, got error: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with deprecated --pk flag")
	}
}

// TestRSEncodeCommand_DeprecatedPayloadFlag tests deprecated --p flag
// Note: This test can be removed when deprecated flags are removed from the CLI
func TestRSEncodeCommand_DeprecatedPayloadFlag(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	// Test deprecated --p flag
	output, err := executeCommand(cmd,
		"--p", validPayload,
		"--private-key", privateKey,
	)

	if err != nil {
		t.Fatalf("Expected deprecated --p flag to work, got error: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with deprecated --p flag")
	}
}

// TestRSEncodeCommand_MixedFlags tests mixing new and deprecated flags
func TestRSEncodeCommand_MixedFlags(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	// Mix new and deprecated flags
	output, err := executeCommand(cmd,
		"--payload", validPayload,
		"--pk", privateKey, // deprecated flag
	)

	if err != nil {
		t.Fatalf("Expected mixed flags to work, got error: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with mixed flags")
	}
}

// TestRSEncodeCommand_EmptyPayload tests error handling for empty payload
func TestRSEncodeCommand_EmptyPayload(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", "",
		"--private-key", privateKey,
	)

	if err == nil {
		t.Fatal("Expected error for empty payload, got nil")
	}

	if !strings.Contains(err.Error(), "payload is mandatory") {
		t.Errorf("Expected 'payload is mandatory' error, got: %v", err)
	}
}

// TestRSEncodeCommand_EmptyPrivateKey tests error handling for empty private key path
func TestRSEncodeCommand_EmptyPrivateKey(t *testing.T) {
	cmd := createRSEncodeCommand(
		"RS256",
		"rs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewRS256Encoder,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", validPayload,
		"--private-key", "",
	)

	if err == nil {
		t.Fatal("Expected error for empty private key, got nil")
	}

	if !strings.Contains(err.Error(), "private key file is mandatory") {
		t.Errorf("Expected 'private key file is mandatory' error, got: %v", err)
	}
}
