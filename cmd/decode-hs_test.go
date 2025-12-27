package cmd

import (
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// TestHSDecodeCommand_Success tests successful JWT decoding for all HS algorithms
func TestHSDecodeCommand_Success(t *testing.T) {
	tests := []struct {
		name            string
		algorithm       string
		encoderConstructor func([]byte, bool) cryptojwt.EncoderDecoder
		decoderConstructor func([]byte, bool, cryptojwt.ValidationOptions) cryptojwt.EncoderDecoder
		secret          string
	}{
		{
			name:            "HS256 valid decoding",
			algorithm:       "hs256",
			encoderConstructor: cryptojwt.NewHS256EncoderWithOptions,
			decoderConstructor: cryptojwt.NewHS256DecoderWithValidation,
			secret:          hs256Secret,
		},
		{
			name:            "HS384 valid decoding",
			algorithm:       "hs384",
			encoderConstructor: cryptojwt.NewHS384EncoderWithOptions,
			decoderConstructor: cryptojwt.NewHS384DecoderWithValidation,
			secret:          hs384Secret,
		},
		{
			name:            "HS512 valid decoding",
			algorithm:       "hs512",
			encoderConstructor: cryptojwt.NewHS512EncoderWithOptions,
			decoderConstructor: cryptojwt.NewHS512DecoderWithValidation,
			secret:          hs512Secret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First encode a token to decode
			encodeCmd := createHSEncodeCommand(
				strings.ToUpper(tt.algorithm),
				tt.algorithm,
				"Test",
				"Test",
				"Test",
				tt.encoderConstructor,
			)
			registerEncodeFlags(encodeCmd)

			tokenOutput, err := executeCommand(encodeCmd,
				"--payload", validPayload,
				"--secret", tt.secret,
			)
			if err != nil {
				t.Fatalf("Failed to encode token: %v", err)
			}
			token := strings.TrimSpace(tokenOutput)

			// Now decode it
			decodeCmd := createHSDecodeCommand(
				strings.ToUpper(tt.algorithm),
				tt.algorithm,
				"Test",
				"Test",
				"Test",
				tt.decoderConstructor,
			)
			registerDecodeFlags(decodeCmd)

			output, err := executeCommand(decodeCmd,
				"--token", token,
				"--secret", tt.secret,
			)

			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			payload := strings.TrimSpace(output)
			if payload == "" {
				t.Fatal("Expected payload output, got empty string")
			}

			// Verify payload contains expected data
			if !strings.Contains(payload, "John Doe") {
				t.Errorf("Expected payload to contain 'John Doe', got: %s", payload)
			}
		})
	}
}

// TestHSDecodeCommand_MissingToken tests error when token flag is missing
func TestHSDecodeCommand_MissingToken(t *testing.T) {
	cmd := createHSDecodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256DecoderWithValidation,
	)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--secret", hs256Secret,
		// Missing --token flag
	)

	if err == nil {
		t.Fatal("Expected error for missing token, got nil")
	}

	if !strings.Contains(err.Error(), "token is required") {
		t.Errorf("Expected 'token is required' error, got: %v", err)
	}
}

// TestHSDecodeCommand_MissingSecret tests error when secret flag is missing
func TestHSDecodeCommand_MissingSecret(t *testing.T) {
	cmd := createHSDecodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256DecoderWithValidation,
	)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidmFsdWUifQ.invalid",
		// Missing --secret flag
	)

	if err == nil {
		t.Fatal("Expected error for missing secret, got nil")
	}

	if !strings.Contains(err.Error(), "secret is required") {
		t.Errorf("Expected 'secret is required' error, got: %v", err)
	}
}

// TestHSDecodeCommand_InvalidToken tests error handling for invalid token format
func TestHSDecodeCommand_InvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "malformed JWT (missing parts)",
			token: "invalid.token",
		},
		{
			name:  "invalid base64",
			token: "not.a.token",
		},
		{
			name:  "empty token parts",
			token: "..",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := createHSDecodeCommand(
				"HS256",
				"hs256",
				"Test",
				"Test",
				"Test",
				cryptojwt.NewHS256DecoderWithValidation,
			)
			registerDecodeFlags(cmd)

			_, err := executeCommand(cmd,
				"--token", tt.token,
				"--secret", hs256Secret,
			)

			if err == nil {
				t.Fatalf("Expected error for invalid token, got nil")
			}
		})
	}
}

// TestHSDecodeCommand_WrongSecret tests decoding with incorrect secret
func TestHSDecodeCommand_WrongSecret(t *testing.T) {
	// First encode a token with one secret
	encodeCmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(encodeCmd)

	tokenOutput, err := executeCommand(encodeCmd,
		"--payload", validPayload,
		"--secret", hs256Secret,
	)
	if err != nil {
		t.Fatalf("Failed to encode token: %v", err)
	}
	token := strings.TrimSpace(tokenOutput)

	// Try to decode with a different secret
	decodeCmd := createHSDecodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256DecoderWithValidation,
	)
	registerDecodeFlags(decodeCmd)

	wrongSecret := "wrong-secret-that-is-32-bytes!!"
	_, err = executeCommand(decodeCmd,
		"--token", token,
		"--secret", wrongSecret,
		"--allow-weak-secret",
	)

	if err == nil {
		t.Fatal("Expected error for wrong secret, got nil")
	}

	if !strings.Contains(err.Error(), "signature") && !strings.Contains(err.Error(), "decoding failed") {
		t.Logf("Expected signature verification error, got: %v", err)
	}
}

// TestHSDecodeCommand_WeakSecret tests secret length validation
func TestHSDecodeCommand_WeakSecret(t *testing.T) {
	tests := []struct {
		name            string
		encoderConstructor func([]byte, bool) cryptojwt.EncoderDecoder
		decoderConstructor func([]byte, bool, cryptojwt.ValidationOptions) cryptojwt.EncoderDecoder
		secret          string
		expectError     string
	}{
		{
			name:            "HS256 requires 32 bytes",
			encoderConstructor: cryptojwt.NewHS256EncoderWithOptions,
			decoderConstructor: cryptojwt.NewHS256DecoderWithValidation,
			secret:          hs256Secret,
			expectError:     "secret must be at least 32 bytes",
		},
		{
			name:            "HS384 requires 48 bytes",
			encoderConstructor: cryptojwt.NewHS384EncoderWithOptions,
			decoderConstructor: cryptojwt.NewHS384DecoderWithValidation,
			secret:          hs384Secret,
			expectError:     "secret must be at least 48 bytes",
		},
		{
			name:            "HS512 requires 64 bytes",
			encoderConstructor: cryptojwt.NewHS512EncoderWithOptions,
			decoderConstructor: cryptojwt.NewHS512DecoderWithValidation,
			secret:          hs512Secret,
			expectError:     "secret must be at least 64 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_without_flag", func(t *testing.T) {
			// Create a token first with weak secret and allow-weak-secret flag
			encodeCmd := createHSEncodeCommand(
				"TEST",
				"test",
				"Test",
				"Test",
				"Test",
				tt.encoderConstructor,
			)
			registerEncodeFlags(encodeCmd)

			tokenOutput, err := executeCommand(encodeCmd,
				"--payload", validPayload,
				"--secret", weakSecret,
				"--allow-weak-secret",
			)
			if err != nil {
				t.Fatalf("Failed to encode with weak secret: %v", err)
			}
			token := strings.TrimSpace(tokenOutput)

			// Try to decode without --allow-weak-secret flag (should fail)
			decodeCmd := createHSDecodeCommand(
				"TEST",
				"test",
				"Test",
				"Test",
				"Test",
				tt.decoderConstructor,
			)
			registerDecodeFlags(decodeCmd)

			_, err = executeCommand(decodeCmd,
				"--token", token,
				"--secret", weakSecret,
			)

			if err == nil {
				t.Fatal("Expected error for weak secret, got nil")
			}
		})

		t.Run(tt.name+"_with_flag", func(t *testing.T) {
			// Create a token first
			encodeCmd := createHSEncodeCommand(
				"TEST",
				"test",
				"Test",
				"Test",
				"Test",
				tt.encoderConstructor,
			)
			registerEncodeFlags(encodeCmd)

			tokenOutput, err := executeCommand(encodeCmd,
				"--payload", validPayload,
				"--secret", weakSecret,
				"--allow-weak-secret",
			)
			if err != nil {
				t.Fatalf("Failed to encode: %v", err)
			}
			token := strings.TrimSpace(tokenOutput)

			// Decode with --allow-weak-secret flag (should succeed)
			decodeCmd := createHSDecodeCommand(
				"TEST",
				"test",
				"Test",
				"Test",
				"Test",
				tt.decoderConstructor,
			)
			registerDecodeFlags(decodeCmd)

			output, err := executeCommand(decodeCmd,
				"--token", token,
				"--secret", weakSecret,
				"--allow-weak-secret",
			)

			if err != nil {
				t.Errorf("Expected no error with --allow-weak-secret, got: %v", err)
			}

			payload := strings.TrimSpace(output)
			if payload == "" {
				t.Error("Expected payload output with --allow-weak-secret")
			}
		})
	}
}

// TestHSDecodeCommand_DeprecatedTokenFlag tests deprecated --t flag
// Note: This test can be removed when deprecated flags are removed from the CLI
func TestHSDecodeCommand_DeprecatedTokenFlag(t *testing.T) {
	// Create a token first
	encodeCmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(encodeCmd)

	tokenOutput, err := executeCommand(encodeCmd,
		"--payload", validPayload,
		"--secret", hs256Secret,
	)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}
	token := strings.TrimSpace(tokenOutput)

	// Test deprecated --t flag
	decodeCmd := createHSDecodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256DecoderWithValidation,
	)
	registerDecodeFlags(decodeCmd)

	output, err := executeCommand(decodeCmd,
		"--t", token,
		"--secret", hs256Secret,
	)

	if err != nil {
		t.Fatalf("Expected deprecated --t flag to work, got error: %v", err)
	}

	payload := strings.TrimSpace(output)
	if payload == "" {
		t.Error("Expected payload output with deprecated --t flag")
	}
}

// TestHSDecodeCommand_DeprecatedSecretFlag tests deprecated --s flag
// Note: This test can be removed when deprecated flags are removed from the CLI
func TestHSDecodeCommand_DeprecatedSecretFlag(t *testing.T) {
	// Create a token first
	encodeCmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(encodeCmd)

	tokenOutput, err := executeCommand(encodeCmd,
		"--payload", validPayload,
		"--secret", hs256Secret,
	)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}
	token := strings.TrimSpace(tokenOutput)

	// Test deprecated --s flag
	decodeCmd := createHSDecodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256DecoderWithValidation,
	)
	registerDecodeFlags(decodeCmd)

	output, err := executeCommand(decodeCmd,
		"--token", token,
		"--s", hs256Secret,
	)

	if err != nil {
		t.Fatalf("Expected deprecated --s flag to work, got error: %v", err)
	}

	payload := strings.TrimSpace(output)
	if payload == "" {
		t.Error("Expected payload output with deprecated --s flag")
	}
}

// TestHSDecodeCommand_EmptyToken tests error handling for empty token
func TestHSDecodeCommand_EmptyToken(t *testing.T) {
	cmd := createHSDecodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256DecoderWithValidation,
	)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--token", "",
		"--secret", hs256Secret,
	)

	if err == nil {
		t.Fatal("Expected error for empty token, got nil")
	}

	if !strings.Contains(err.Error(), "token is required") {
		t.Errorf("Expected 'token is required' error, got: %v", err)
	}
}

// TestHSDecodeCommand_EmptySecret tests error handling for empty secret
func TestHSDecodeCommand_EmptySecret(t *testing.T) {
	cmd := createHSDecodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256DecoderWithValidation,
	)
	registerDecodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidmFsdWUifQ.test",
		"--secret", "",
	)

	if err == nil {
		t.Fatal("Expected error for empty secret, got nil")
	}

	if !strings.Contains(err.Error(), "secret is required") {
		t.Errorf("Expected 'secret is required' error, got: %v", err)
	}
}
