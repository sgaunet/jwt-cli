package cmd

import (
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// TestESEncodeCommand_Success tests successful JWT encoding for all ES algorithms
func TestESEncodeCommand_Success(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		constructor func(string) cryptojwt.Encoder
		curve       elliptic.Curve
	}{
		{"ES256 valid encoding", "es256", cryptojwt.NewES256Encoder, elliptic.P256()},
		{"ES384 valid encoding", "es384", cryptojwt.NewES384Encoder, elliptic.P384()},
		{"ES512 valid encoding", "es512", cryptojwt.NewES512Encoder, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, _ := generateECDSAKeyPair(t, tt.curve)

			cmd := createESEncodeCommand(strings.ToUpper(tt.algorithm), tt.algorithm, "Test", "Test", "Test", tt.constructor)
			registerEncodeFlags(cmd)

			output, err := executeCommand(cmd, "--payload", validPayload, "--private-key", privateKey)

			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			token := strings.TrimSpace(output)
			if token == "" {
				t.Fatal("Expected token output")
			}

			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("Expected JWT with 3 parts, got %d parts", len(parts))
			}
		})
	}
}

// TestESEncodeCommand_MissingPrivateKey tests error when private-key flag is missing
func TestESEncodeCommand_MissingPrivateKey(t *testing.T) {
	cmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--payload", validPayload)

	if err == nil {
		t.Fatal("Expected error for missing private key, got nil")
	}

	if !strings.Contains(err.Error(), "private key file is mandatory") {
		t.Errorf("Expected 'private key file is mandatory' error, got: %v", err)
	}
}

// TestESEncodeCommand_MissingPayload tests error when payload flag is missing
func TestESEncodeCommand_MissingPayload(t *testing.T) {
	privateKey, _ := generateECDSAKeyPair(t, elliptic.P256())

	cmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--private-key", privateKey)

	if err == nil {
		t.Fatal("Expected error for missing payload, got nil")
	}

	if !strings.Contains(err.Error(), "payload is mandatory") {
		t.Errorf("Expected 'payload is mandatory' error, got: %v", err)
	}
}

// TestESEncodeCommand_InvalidJSON tests error handling for invalid JSON
func TestESEncodeCommand_InvalidJSON(t *testing.T) {
	privateKey, _ := generateECDSAKeyPair(t, elliptic.P256())

	cmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--payload", invalidJSON, "--private-key", privateKey)

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
}

// TestESEncodeCommand_NonExistentKeyFile tests error for missing key file
func TestESEncodeCommand_NonExistentKeyFile(t *testing.T) {
	cmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--payload", validPayload, "--private-key", getNonExistentPath(t))

	if err == nil {
		t.Fatal("Expected error for nonexistent key file, got nil")
	}
}

// TestESEncodeCommand_WrongKeyType tests error when using RSA key instead of ECDSA
func TestESEncodeCommand_WrongKeyType(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	cmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--payload", validPayload, "--private-key", privateKey)

	if err == nil {
		t.Fatal("Expected error for wrong key type, got nil")
	}
}

// TestESEncodeCommand_MalformedKey tests error for malformed ECDSA key
func TestESEncodeCommand_MalformedKey(t *testing.T) {
	malformedKey := createMalformedECKeyFile(t)

	cmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--payload", validPayload, "--private-key", malformedKey)

	if err == nil {
		t.Fatal("Expected error for malformed key, got nil")
	}
}

// TestESEncodeCommand_DeprecatedFlags tests deprecated flags
func TestESEncodeCommand_DeprecatedFlags(t *testing.T) {
	privateKey, _ := generateECDSAKeyPair(t, elliptic.P256())

	cmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(cmd)

	output, err := executeCommand(cmd, "--p", validPayload, "--pk", privateKey)

	if err != nil {
		t.Fatalf("Expected deprecated flags to work, got: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with deprecated flags")
	}
}
