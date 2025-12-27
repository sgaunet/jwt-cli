package cmd

import (
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// TestESDecodeCommand_Success tests successful JWT decoding for all ES algorithms
func TestESDecodeCommand_Success(t *testing.T) {
	tests := []struct {
		name           string
		algorithm      string
		encoder        func(string) cryptojwt.Encoder
		pubKeyDecoder  func(string, cryptojwt.ValidationOptions) cryptojwt.Decoder
		privKeyDecoder func(string, cryptojwt.ValidationOptions) cryptojwt.Decoder
		curve          elliptic.Curve
	}{
		{"ES256 decode with public key", "es256", cryptojwt.NewES256Encoder, cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation, elliptic.P256()},
		{"ES384 decode with public key", "es384", cryptojwt.NewES384Encoder, cryptojwt.NewES384DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES384DecoderWithPrivateKeyFileAndValidation, elliptic.P384()},
		{"ES512 decode with public key", "es512", cryptojwt.NewES512Encoder, cryptojwt.NewES512DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES512DecoderWithPrivateKeyFileAndValidation, elliptic.P521()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, publicKey := generateECDSAKeyPair(t, tt.curve)

			// Encode
			encodeCmd := createESEncodeCommand(strings.ToUpper(tt.algorithm), tt.algorithm, "Test", "Test", "Test", tt.encoder)
			registerEncodeFlags(encodeCmd)
			tokenOutput, err := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}
			token := strings.TrimSpace(tokenOutput)

			// Decode with public key
			decodeCmd := createESDecodeCommand(strings.ToUpper(tt.algorithm), tt.algorithm, "Test", "Test", "Test", tt.pubKeyDecoder, tt.privKeyDecoder)
			registerDecodeFlags(decodeCmd)

			output, err := executeCommand(decodeCmd, "--token", token, "--public-key", publicKey)

			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			payload := strings.TrimSpace(output)
			if !strings.Contains(payload, "John Doe") {
				t.Errorf("Expected payload to contain 'John Doe', got: %s", payload)
			}
		})
	}
}

// TestESDecodeCommand_WithPrivateKey tests decoding with private key
func TestESDecodeCommand_WithPrivateKey(t *testing.T) {
	privateKey, _ := generateECDSAKeyPair(t, elliptic.P256())

	// Encode
	encodeCmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(encodeCmd)
	tokenOutput, _ := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey)
	token := strings.TrimSpace(tokenOutput)

	// Decode with private key
	decodeCmd := createESDecodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation)
	registerDecodeFlags(decodeCmd)

	output, err := executeCommand(decodeCmd, "--token", token, "--private-key", privateKey)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	payload := strings.TrimSpace(output)
	if !strings.Contains(payload, "John Doe") {
		t.Error("Expected valid payload")
	}
}

// TestESDecodeCommand_MissingKeys tests error when both keys are missing
func TestESDecodeCommand_MissingKeys(t *testing.T) {
	cmd := createESDecodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--token", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.test.test")

	if err == nil {
		t.Fatal("Expected error for missing keys, got nil")
	}

	if !strings.Contains(err.Error(), "key file is required") {
		t.Errorf("Expected key required error, got: %v", err)
	}
}

// TestESDecodeCommand_MissingToken tests error when token is missing
func TestESDecodeCommand_MissingToken(t *testing.T) {
	_, publicKey := generateECDSAKeyPair(t, elliptic.P256())

	cmd := createESDecodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--public-key", publicKey)

	if err == nil {
		t.Fatal("Expected error for missing token, got nil")
	}

	if !strings.Contains(err.Error(), "token is required") {
		t.Errorf("Expected token required error, got: %v", err)
	}
}

// TestESDecodeCommand_InvalidToken tests invalid token handling
func TestESDecodeCommand_InvalidToken(t *testing.T) {
	_, publicKey := generateECDSAKeyPair(t, elliptic.P256())

	cmd := createESDecodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--token", "invalid.token", "--public-key", publicKey)

	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
}

// TestESDecodeCommand_WrongKey tests decoding with mismatched key
func TestESDecodeCommand_WrongKey(t *testing.T) {
	privateKey1, _ := generateECDSAKeyPair(t, elliptic.P256())
	_, publicKey2 := generateECDSAKeyPair(t, elliptic.P256())

	// Encode with first key
	encodeCmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(encodeCmd)
	tokenOutput, _ := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey1)
	token := strings.TrimSpace(tokenOutput)

	// Try to decode with second key
	decodeCmd := createESDecodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation)
	registerDecodeFlags(decodeCmd)

	_, err := executeCommand(decodeCmd, "--token", token, "--public-key", publicKey2)

	if err == nil {
		t.Fatal("Expected error for wrong key, got nil")
	}
}

// TestESDecodeCommand_DeprecatedFlags tests deprecated flags
func TestESDecodeCommand_DeprecatedFlags(t *testing.T) {
	privateKey, publicKey := generateECDSAKeyPair(t, elliptic.P256())

	// Encode
	encodeCmd := createESEncodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256Encoder)
	registerEncodeFlags(encodeCmd)
	tokenOutput, _ := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey)
	token := strings.TrimSpace(tokenOutput)

	// Decode with deprecated flags
	decodeCmd := createESDecodeCommand("ES256", "es256", "Test", "Test", "Test", cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation, cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation)
	registerDecodeFlags(decodeCmd)

	output, err := executeCommand(decodeCmd, "--t", token, "--pubk", publicKey)

	if err != nil {
		t.Fatalf("Expected deprecated flags to work, got: %v", err)
	}

	payload := strings.TrimSpace(output)
	if payload == "" {
		t.Error("Expected payload output with deprecated flags")
	}
}
