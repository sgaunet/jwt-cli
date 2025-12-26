package cmd

import (
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// TestRSDecodeCommand_SuccessWithPublicKey tests decoding with public key
func TestRSDecodeCommand_SuccessWithPublicKey(t *testing.T) {
	tests := []struct {
		name               string
		algorithm          string
		encoder            func(string) cryptojwt.Encoder
		pubKeyDecoder      func(string) cryptojwt.Decoder
		privKeyDecoder     func(string) cryptojwt.Decoder
	}{
		{
			name:           "RS256 decode with public key",
			algorithm:      "rs256",
			encoder:        cryptojwt.NewRS256Encoder,
			pubKeyDecoder:  cryptojwt.NewRS256DecoderWithPublicKeyFile,
			privKeyDecoder: cryptojwt.NewRS256DecoderWithPrivateKeyFile,
		},
		{
			name:           "RS384 decode with public key",
			algorithm:      "rs384",
			encoder:        cryptojwt.NewRS384Encoder,
			pubKeyDecoder:  cryptojwt.NewRS384DecoderWithPublicKeyFile,
			privKeyDecoder: cryptojwt.NewRS384DecoderWithPrivateKeyFile,
		},
		{
			name:           "RS512 decode with public key",
			algorithm:      "rs512",
			encoder:        cryptojwt.NewRS512Encoder,
			pubKeyDecoder:  cryptojwt.NewRS512DecoderWithPublicKeyFile,
			privKeyDecoder: cryptojwt.NewRS512DecoderWithPrivateKeyFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, publicKey := generateRSAKeyPair(t)

			// First encode a token
			encodeCmd := createRSEncodeCommand(
				strings.ToUpper(tt.algorithm),
				tt.algorithm,
				"Test",
				"Test",
				"Test",
				tt.encoder,
			)
			registerEncodeFlags(encodeCmd)

			tokenOutput, err := executeCommand(encodeCmd,
				"--payload", validPayload,
				"--private-key", privateKey,
			)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}
			token := strings.TrimSpace(tokenOutput)

			// Now decode with public key
			decodeCmd := createRSDecodeCommand(
				strings.ToUpper(tt.algorithm),
				tt.algorithm,
				"Test",
				"Test",
				"Test",
				tt.pubKeyDecoder,
				tt.privKeyDecoder,
			)
			registerDecodeFlags(decodeCmd)

			output, err := executeCommand(decodeCmd,
				"--token", token,
				"--public-key", publicKey,
			)

			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			payload := strings.TrimSpace(output)
			if payload == "" {
				t.Fatal("Expected payload output")
			}

			if !strings.Contains(payload, "John Doe") {
				t.Errorf("Expected payload to contain 'John Doe', got: %s", payload)
			}
		})
	}
}

// TestRSDecodeCommand_SuccessWithPrivateKey tests decoding with private key
func TestRSDecodeCommand_SuccessWithPrivateKey(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	// Encode
	encodeCmd := createRSEncodeCommand("RS256", "rs256", "Test", "Test", "Test", cryptojwt.NewRS256Encoder)
	registerEncodeFlags(encodeCmd)
	tokenOutput, _ := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey)
	token := strings.TrimSpace(tokenOutput)

	// Decode with private key
	decodeCmd := createRSDecodeCommand("RS256", "rs256", "Test", "Test", "Test",
		cryptojwt.NewRS256DecoderWithPublicKeyFile, cryptojwt.NewRS256DecoderWithPrivateKeyFile)
	registerDecodeFlags(decodeCmd)

	output, err := executeCommand(decodeCmd, "--token", token, "--private-key", privateKey)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	payload := strings.TrimSpace(output)
	if !strings.Contains(payload, "John Doe") {
		t.Errorf("Expected payload to contain 'John Doe', got: %s", payload)
	}
}

// TestRSDecodeCommand_MissingKeys tests error when both keys are missing
func TestRSDecodeCommand_MissingKeys(t *testing.T) {
	cmd := createRSDecodeCommand("RS256", "rs256", "Test", "Test", "Test",
		cryptojwt.NewRS256DecoderWithPublicKeyFile, cryptojwt.NewRS256DecoderWithPrivateKeyFile)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--token", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.test")

	if err == nil {
		t.Fatal("Expected error for missing keys, got nil")
	}

	if !strings.Contains(err.Error(), "private key file or public key file is mandatory") {
		t.Errorf("Expected key mandatory error, got: %v", err)
	}
}

// TestRSDecodeCommand_MissingToken tests error when token is missing
func TestRSDecodeCommand_MissingToken(t *testing.T) {
	_, publicKey := generateRSAKeyPair(t)

	cmd := createRSDecodeCommand("RS256", "rs256", "Test", "Test", "Test",
		cryptojwt.NewRS256DecoderWithPublicKeyFile, cryptojwt.NewRS256DecoderWithPrivateKeyFile)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--public-key", publicKey)

	if err == nil {
		t.Fatal("Expected error for missing token, got nil")
	}

	if !strings.Contains(err.Error(), "token is mandatory") {
		t.Errorf("Expected token mandatory error, got: %v", err)
	}
}

// TestRSDecodeCommand_InvalidToken tests invalid token handling
func TestRSDecodeCommand_InvalidToken(t *testing.T) {
	_, publicKey := generateRSAKeyPair(t)

	cmd := createRSDecodeCommand("RS256", "rs256", "Test", "Test", "Test",
		cryptojwt.NewRS256DecoderWithPublicKeyFile, cryptojwt.NewRS256DecoderWithPrivateKeyFile)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--token", "invalid.token", "--public-key", publicKey)

	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
}

// TestRSDecodeCommand_WrongKey tests decoding with mismatched key
func TestRSDecodeCommand_WrongKey(t *testing.T) {
	privateKey1, _ := generateRSAKeyPair(t)
	_, publicKey2 := generateRSAKeyPair(t) // Different key pair

	// Encode with first key
	encodeCmd := createRSEncodeCommand("RS256", "rs256", "Test", "Test", "Test", cryptojwt.NewRS256Encoder)
	registerEncodeFlags(encodeCmd)
	tokenOutput, _ := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey1)
	token := strings.TrimSpace(tokenOutput)

	// Try to decode with second key
	decodeCmd := createRSDecodeCommand("RS256", "rs256", "Test", "Test", "Test",
		cryptojwt.NewRS256DecoderWithPublicKeyFile, cryptojwt.NewRS256DecoderWithPrivateKeyFile)
	registerDecodeFlags(decodeCmd)

	_, err := executeCommand(decodeCmd, "--token", token, "--public-key", publicKey2)

	if err == nil {
		t.Fatal("Expected error for wrong key, got nil")
	}
}

// TestRSDecodeCommand_PublicKeyPrecedence tests that public key is used when both are provided
func TestRSDecodeCommand_PublicKeyPrecedence(t *testing.T) {
	privateKey, publicKey := generateRSAKeyPair(t)

	// Encode
	encodeCmd := createRSEncodeCommand("RS256", "rs256", "Test", "Test", "Test", cryptojwt.NewRS256Encoder)
	registerEncodeFlags(encodeCmd)
	tokenOutput, _ := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey)
	token := strings.TrimSpace(tokenOutput)

	// Decode with both keys (public should take precedence)
	decodeCmd := createRSDecodeCommand("RS256", "rs256", "Test", "Test", "Test",
		cryptojwt.NewRS256DecoderWithPublicKeyFile, cryptojwt.NewRS256DecoderWithPrivateKeyFile)
	registerDecodeFlags(decodeCmd)

	output, err := executeCommand(decodeCmd, "--token", token, "--public-key", publicKey, "--private-key", privateKey)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	payload := strings.TrimSpace(output)
	if !strings.Contains(payload, "John Doe") {
		t.Error("Expected valid payload with both keys")
	}
}

// TestRSDecodeCommand_NonExistentPublicKey tests error for missing public key file
func TestRSDecodeCommand_NonExistentPublicKey(t *testing.T) {
	privateKey, _ := generateRSAKeyPair(t)

	// Encode
	encodeCmd := createRSEncodeCommand("RS256", "rs256", "Test", "Test", "Test", cryptojwt.NewRS256Encoder)
	registerEncodeFlags(encodeCmd)
	tokenOutput, _ := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey)
	token := strings.TrimSpace(tokenOutput)

	// Try to decode with nonexistent public key
	decodeCmd := createRSDecodeCommand("RS256", "rs256", "Test", "Test", "Test",
		cryptojwt.NewRS256DecoderWithPublicKeyFile, cryptojwt.NewRS256DecoderWithPrivateKeyFile)
	registerDecodeFlags(decodeCmd)

	nonExistent := getNonExistentPath(t)
	_, err := executeCommand(decodeCmd, "--token", token, "--public-key", nonExistent)

	if err == nil {
		t.Fatal("Expected error for nonexistent file, got nil")
	}
}

// TestRSDecodeCommand_DeprecatedFlags tests deprecated flags
func TestRSDecodeCommand_DeprecatedFlags(t *testing.T) {
	privateKey, publicKey := generateRSAKeyPair(t)

	// Encode
	encodeCmd := createRSEncodeCommand("RS256", "rs256", "Test", "Test", "Test", cryptojwt.NewRS256Encoder)
	registerEncodeFlags(encodeCmd)
	tokenOutput, _ := executeCommand(encodeCmd, "--payload", validPayload, "--private-key", privateKey)
	token := strings.TrimSpace(tokenOutput)

	tests := []struct {
		name string
		args []string
	}{
		{"deprecated --pubk", []string{"--t", token, "--pubk", publicKey}},
		{"deprecated --pk", []string{"--t", token, "--pk", privateKey}},
		{"deprecated --t with public key", []string{"--t", token, "--public-key", publicKey}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decodeCmd := createRSDecodeCommand("RS256", "rs256", "Test", "Test", "Test",
				cryptojwt.NewRS256DecoderWithPublicKeyFile, cryptojwt.NewRS256DecoderWithPrivateKeyFile)
			registerDecodeFlags(decodeCmd)

			output, err := executeCommand(decodeCmd, tt.args...)

			if err != nil {
				t.Fatalf("Expected deprecated flags to work, got: %v", err)
			}

			payload := strings.TrimSpace(output)
			if payload == "" {
				t.Error("Expected payload output with deprecated flags")
			}
		})
	}
}
