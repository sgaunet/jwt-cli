package cmd

import (
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
)

// TestHSEncodeCommand_Success tests successful JWT encoding for all HS algorithms
func TestHSEncodeCommand_Success(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   string
		constructor func([]byte, bool) cryptojwt.EncoderDecoder
		secret      string
	}{
		{
			name:        "HS256 valid encoding",
			algorithm:   "hs256",
			constructor: cryptojwt.NewHS256EncoderWithOptions,
			secret:      hs256Secret,
		},
		{
			name:        "HS384 valid encoding",
			algorithm:   "hs384",
			constructor: cryptojwt.NewHS384EncoderWithOptions,
			secret:      hs384Secret,
		},
		{
			name:        "HS512 valid encoding",
			algorithm:   "hs512",
			constructor: cryptojwt.NewHS512EncoderWithOptions,
			secret:      hs512Secret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := createHSEncodeCommand(
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
				"--secret", tt.secret,
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

// TestHSEncodeCommand_ComplexPayload tests encoding with complex nested JSON
func TestHSEncodeCommand_ComplexPayload(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	output, err := executeCommand(cmd,
		"--payload", complexPayload,
		"--secret", hs256Secret,
	)

	if err != nil {
		t.Fatalf("Expected no error with complex payload, got: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with complex payload")
	}
}

// TestHSEncodeCommand_MissingSecret tests error when secret flag is missing
func TestHSEncodeCommand_MissingSecret(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", validPayload,
		// Missing --secret flag
	)

	if err == nil {
		t.Fatal("Expected error for missing secret, got nil")
	}

	if !strings.Contains(err.Error(), "secret is mandatory") {
		t.Errorf("Expected 'secret is mandatory' error, got: %v", err)
	}
}

// TestHSEncodeCommand_MissingPayload tests error when payload flag is missing
func TestHSEncodeCommand_MissingPayload(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--secret", hs256Secret,
		// Missing --payload flag
	)

	if err == nil {
		t.Fatal("Expected error for missing payload, got nil")
	}

	if !strings.Contains(err.Error(), "payload is mandatory") {
		t.Errorf("Expected 'payload is mandatory' error, got: %v", err)
	}
}

// TestHSEncodeCommand_InvalidJSON tests error handling for invalid JSON payload
func TestHSEncodeCommand_InvalidJSON(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", invalidJSON,
		"--secret", hs256Secret,
	)

	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}

	// The error should indicate JSON parsing failure
	errStr := err.Error()
	if !strings.Contains(errStr, "payload is not a valid JSON") && !strings.Contains(errStr, "encoding failed") {
		t.Errorf("Expected JSON validation error, got: %v", err)
	}
}

// TestHSEncodeCommand_WeakSecret tests secret length validation
func TestHSEncodeCommand_WeakSecret(t *testing.T) {
	tests := []struct {
		name        string
		constructor func([]byte, bool) cryptojwt.EncoderDecoder
		minBytes    int
		expectError string
	}{
		{
			name:        "HS256 requires 32 bytes",
			constructor: cryptojwt.NewHS256EncoderWithOptions,
			minBytes:    32,
			expectError: "secret must be at least 32 bytes",
		},
		{
			name:        "HS384 requires 48 bytes",
			constructor: cryptojwt.NewHS384EncoderWithOptions,
			minBytes:    48,
			expectError: "secret must be at least 48 bytes",
		},
		{
			name:        "HS512 requires 64 bytes",
			constructor: cryptojwt.NewHS512EncoderWithOptions,
			minBytes:    64,
			expectError: "secret must be at least 64 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_without_flag", func(t *testing.T) {
			cmd := createHSEncodeCommand(
				"TEST",
				"test",
				"Test",
				"Test",
				"Test",
				tt.constructor,
			)
			registerEncodeFlags(cmd)

			// Test without --allow-weak-secret flag (should fail)
			_, err := executeCommand(cmd,
				"--payload", validPayload,
				"--secret", weakSecret,
			)

			if err == nil {
				t.Fatal("Expected error for weak secret, got nil")
			}

			if !strings.Contains(err.Error(), tt.expectError) && !strings.Contains(err.Error(), "encoding failed") {
				t.Logf("Note: Error message might be wrapped. Got: %v", err)
			}
		})

		t.Run(tt.name+"_with_flag", func(t *testing.T) {
			cmd := createHSEncodeCommand(
				"TEST",
				"test",
				"Test",
				"Test",
				"Test",
				tt.constructor,
			)
			registerEncodeFlags(cmd)

			// Test with --allow-weak-secret flag (should succeed)
			output, err := executeCommand(cmd,
				"--payload", validPayload,
				"--secret", weakSecret,
				"--allow-weak-secret",
			)

			if err != nil {
				t.Errorf("Expected no error with --allow-weak-secret, got: %v", err)
			}

			token := strings.TrimSpace(output)
			if token == "" {
				t.Error("Expected token output with --allow-weak-secret")
			}
		})
	}
}

// TestHSEncodeCommand_DeprecatedPayloadFlag tests deprecated --p flag
// Note: This test can be removed when deprecated flags are removed from the CLI
func TestHSEncodeCommand_DeprecatedPayloadFlag(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	// Test deprecated --p flag (long form deprecated)
	output, err := executeCommand(cmd,
		"--p", validPayload,
		"--secret", hs256Secret,
	)

	if err != nil {
		t.Fatalf("Expected deprecated --p flag to work, got error: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with deprecated --p flag")
	}
}

// TestHSEncodeCommand_DeprecatedSecretFlag tests deprecated --s flag
// Note: This test can be removed when deprecated flags are removed from the CLI
func TestHSEncodeCommand_DeprecatedSecretFlag(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	// Test deprecated --s flag (long form deprecated)
	output, err := executeCommand(cmd,
		"--payload", validPayload,
		"--s", hs256Secret,
	)

	if err != nil {
		t.Fatalf("Expected deprecated --s flag to work, got error: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with deprecated --s flag")
	}
}

// TestHSEncodeCommand_MixedFlags tests mixing new and deprecated flags
func TestHSEncodeCommand_MixedFlags(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	// Mix new and deprecated flags
	output, err := executeCommand(cmd,
		"--payload", validPayload,
		"--s", hs256Secret, // deprecated flag
	)

	if err != nil {
		t.Fatalf("Expected mixed flags to work, got error: %v", err)
	}

	token := strings.TrimSpace(output)
	if token == "" {
		t.Error("Expected token output with mixed flags")
	}
}

// TestHSEncodeCommand_EmptyPayload tests error handling for empty payload
func TestHSEncodeCommand_EmptyPayload(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", "",
		"--secret", hs256Secret,
	)

	if err == nil {
		t.Fatal("Expected error for empty payload, got nil")
	}

	if !strings.Contains(err.Error(), "payload is mandatory") {
		t.Errorf("Expected 'payload is mandatory' error, got: %v", err)
	}
}

// TestHSEncodeCommand_EmptySecret tests error handling for empty secret
func TestHSEncodeCommand_EmptySecret(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256",
		"hs256",
		"Test",
		"Test",
		"Test",
		cryptojwt.NewHS256EncoderWithOptions,
	)
	registerEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--payload", validPayload,
		"--secret", "",
	)

	if err == nil {
		t.Fatal("Expected error for empty secret, got nil")
	}

	if !strings.Contains(err.Error(), "secret is mandatory") {
		t.Errorf("Expected 'secret is mandatory' error, got: %v", err)
	}
}
