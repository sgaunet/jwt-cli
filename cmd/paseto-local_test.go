package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// extractToken pulls a PASETO token out of captured command output, which may
// also carry deprecation notices or usage text.
func extractToken(t *testing.T, out, prefix string) string {
	t.Helper()
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, prefix) {
			return field
		}
	}
	t.Fatalf("Expected a token with prefix %q in output: %s", prefix, out)
	return ""
}

// firstJSON decodes the leading JSON value of out, ignoring any usage text that
// Cobra appends when a standalone command fails.
func firstJSON(t *testing.T, out string) CommandOutput {
	t.Helper()
	var result CommandOutput
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&result); err != nil {
		t.Fatalf("Expected leading JSON value, got %q: %v", out, err)
	}
	return result
}

// encodePasetoLocal encodes a token with a fresh command instance and returns it.
func encodePasetoLocal(t *testing.T, args ...string) string {
	t.Helper()
	cmd := createPasetoEncodeLocalCommand()
	registerPasetoEncodeFlags(cmd)
	out, err := executeCommand(cmd, args...)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}
	return strings.TrimSpace(out)
}

func TestPasetoEncodeLocalCommand_Success(t *testing.T) {
	tests := []struct {
		name    string
		version string
		prefix  string
	}{
		{"v4 local encode", "v4", "v4.local."},
		{"v3 local encode", "v3", "v3.local."},
		{"v2 local encode", "v2", "v2.local."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := encodePasetoLocal(t,
				"--version", tt.version,
				"--key", pasetoTestKey,
				"--payload", validPayload,
			)
			if !strings.HasPrefix(token, tt.prefix) {
				t.Errorf("Expected token to start with %q, got: %s", tt.prefix, token)
			}
		})
	}
}

func TestPasetoDecodeLocalCommand_RoundTrip(t *testing.T) {
	for _, version := range []string{"v4", "v3", "v2"} {
		t.Run(version+" round trip", func(t *testing.T) {
			token := encodePasetoLocal(t,
				"--version", version,
				"--key", pasetoTestKey,
				"--payload", validPayload,
			)

			cmd := createPasetoDecodeLocalCommand()
			registerPasetoDecodeFlags(cmd)
			out, err := executeCommand(cmd,
				"--version", version,
				"--key", pasetoTestKey,
				"--token", token,
			)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			if !strings.Contains(out, "John Doe") {
				t.Errorf("Expected claims to contain 'John Doe', got: %s", out)
			}
		})
	}
}

func TestPasetoEncodeLocalCommand_MissingKey(t *testing.T) {
	cmd := createPasetoEncodeLocalCommand()
	registerPasetoEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--payload", validPayload)
	if err == nil {
		t.Fatal("Expected error for missing key, got nil")
	}
	if !strings.Contains(err.Error(), "key is required") {
		t.Errorf("Expected key required error, got: %v", err)
	}
}

func TestPasetoEncodeLocalCommand_MissingPayload(t *testing.T) {
	cmd := createPasetoEncodeLocalCommand()
	registerPasetoEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--key", pasetoTestKey)
	if err == nil {
		t.Fatal("Expected error for missing payload, got nil")
	}
	if !strings.Contains(err.Error(), "payload is required") {
		t.Errorf("Expected payload required error, got: %v", err)
	}
}

func TestPasetoDecodeLocalCommand_MissingToken(t *testing.T) {
	cmd := createPasetoDecodeLocalCommand()
	registerPasetoDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--key", pasetoTestKey)
	if err == nil {
		t.Fatal("Expected error for missing token, got nil")
	}
	if !strings.Contains(err.Error(), "token is required") {
		t.Errorf("Expected token required error, got: %v", err)
	}
}

func TestPasetoLocalCommand_UnsupportedVersion(t *testing.T) {
	cmd := createPasetoEncodeLocalCommand()
	registerPasetoEncodeFlags(cmd)

	_, err := executeCommand(cmd,
		"--version", "v9",
		"--key", pasetoTestKey,
		"--payload", validPayload,
	)
	if err == nil {
		t.Fatal("Expected error for unsupported version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported PASETO version") {
		t.Errorf("Expected unsupported version error, got: %v", err)
	}
}

func TestPasetoEncodeLocalCommand_InvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{"non-hex key", "not-hex-at-all"},
		{"short key", "deadbeef"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := createPasetoEncodeLocalCommand()
			registerPasetoEncodeFlags(cmd)

			_, err := executeCommand(cmd, "--key", tt.key, "--payload", validPayload)
			if err == nil {
				t.Fatal("Expected error for invalid key, got nil")
			}
			if !strings.Contains(err.Error(), "invalid key") {
				t.Errorf("Expected invalid key error, got: %v", err)
			}
		})
	}
}

func TestPasetoEncodeLocalCommand_InvalidPayload(t *testing.T) {
	cmd := createPasetoEncodeLocalCommand()
	registerPasetoEncodeFlags(cmd)

	_, err := executeCommand(cmd, "--key", pasetoTestKey, "--payload", invalidJSON)
	if err == nil {
		t.Fatal("Expected error for invalid payload, got nil")
	}
	if !strings.Contains(err.Error(), "not a valid JSON") {
		t.Errorf("Expected invalid payload error, got: %v", err)
	}
}

func TestPasetoDecodeLocalCommand_WrongKey(t *testing.T) {
	token := encodePasetoLocal(t, "--key", pasetoTestKey, "--payload", validPayload)

	cmd := createPasetoDecodeLocalCommand()
	registerPasetoDecodeFlags(cmd)
	otherKey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	_, err := executeCommand(cmd, "--key", otherKey, "--token", token)
	if err == nil {
		t.Fatal("Expected error when decoding with the wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "decoding failed") {
		t.Errorf("Expected decoding failure, got: %v", err)
	}
}

func TestPasetoDecodeLocalCommand_MalformedToken(t *testing.T) {
	cmd := createPasetoDecodeLocalCommand()
	registerPasetoDecodeFlags(cmd)

	_, err := executeCommand(cmd, "--key", pasetoTestKey, "--token", "not.a.token")
	if err == nil {
		t.Fatal("Expected error for malformed token, got nil")
	}
	if !strings.Contains(err.Error(), "decoding failed") {
		t.Errorf("Expected decoding failure, got: %v", err)
	}
}

func TestPasetoLocalCommand_DeprecatedFlags(t *testing.T) {
	// The short forms were the only names this command originally accepted, so
	// they must keep working alongside the canonical long names.
	cmd := createPasetoEncodeLocalCommand()
	registerPasetoEncodeFlags(cmd)

	out, err := executeCommand(cmd, "--key", pasetoTestKey, "--p", validPayload)
	if err != nil {
		t.Fatalf("Expected deprecated --p to work, got: %v", err)
	}
	token := extractToken(t, out, "v4.local.")

	decodeCmd := createPasetoDecodeLocalCommand()
	registerPasetoDecodeFlags(decodeCmd)
	if _, err := executeCommand(decodeCmd, "--key", pasetoTestKey, "--t", token); err != nil {
		t.Fatalf("Expected deprecated --t to work, got: %v", err)
	}
}

func TestPasetoLocalCommand_JSONOutput(t *testing.T) {
	// --json must produce the same CommandOutput envelope the JWT commands use.
	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	encodeCmd := createPasetoEncodeLocalCommand()
	registerPasetoEncodeFlags(encodeCmd)
	out, err := executeCommand(encodeCmd, "--key", pasetoTestKey, "--payload", validPayload)
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	encoded := firstJSON(t, out)
	if !encoded.Success {
		t.Errorf("Expected success=true, got: %+v", encoded)
	}
	if !strings.HasPrefix(encoded.Token, "v4.local.") {
		t.Errorf("Expected a v4.local token in the envelope, got: %q", encoded.Token)
	}

	decodeCmd := createPasetoDecodeLocalCommand()
	registerPasetoDecodeFlags(decodeCmd)
	out, err = executeCommand(decodeCmd, "--key", pasetoTestKey, "--token", encoded.Token)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	decoded := firstJSON(t, out)
	if !decoded.Success {
		t.Errorf("Expected success=true, got: %+v", decoded)
	}
	claims, ok := decoded.Claims.(map[string]any)
	if !ok {
		t.Fatalf("Expected claims object, got %T", decoded.Claims)
	}
	if claims["name"] != "John Doe" {
		t.Errorf("Expected name claim 'John Doe', got: %v", claims["name"])
	}
}

func TestPasetoLocalCommand_JSONErrorEnvelope(t *testing.T) {
	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	cmd := createPasetoEncodeLocalCommand()
	registerPasetoEncodeFlags(cmd)
	out, err := executeCommand(cmd, "--key", "deadbeef", "--payload", validPayload)
	if err == nil {
		t.Fatal("Expected error for invalid key, got nil")
	}

	failure := firstJSON(t, out)
	if failure.Success {
		t.Errorf("Expected success=false, got: %+v", failure)
	}
	if failure.Error == "" {
		t.Error("Expected a non-empty error message in the failure envelope")
	}
}

// expiredPasetoPayload renders a payload whose exp claim is already in the past.
func expiredPasetoPayload(age time.Duration) string {
	return fmt.Sprintf(`{"name":"John Doe","exp":%d}`, time.Now().Add(-age).Unix())
}

func TestPasetoDecodeLocalCommand_ValidateClaims(t *testing.T) {
	token := encodePasetoLocal(t,
		"--key", pasetoTestKey,
		"--payload", expiredPasetoPayload(time.Hour),
	)

	t.Run("expired token decodes by default", func(t *testing.T) {
		cmd := createPasetoDecodeLocalCommand()
		registerPasetoDecodeFlags(cmd)

		out, err := executeCommand(cmd, "--key", pasetoTestKey, "--token", token)
		if err != nil {
			t.Fatalf("Expected the expired token to decode by default, got: %v", err)
		}
		if !strings.Contains(out, "John Doe") {
			t.Errorf("Expected claims in output, got: %s", out)
		}
	})

	t.Run("expired token is rejected with --validate-claims", func(t *testing.T) {
		cmd := createPasetoDecodeLocalCommand()
		registerPasetoDecodeFlags(cmd)

		var err error
		stderr := captureStderr(t, func() {
			_, err = executeCommand(cmd, "--key", pasetoTestKey, "--token", token, "--validate-claims")
		})
		if err == nil {
			t.Fatal("Expected an error for an expired token, got nil")
		}
		if !strings.Contains(stderr, "token has expired") {
			t.Errorf("Expected the expiry to be reported, got: %s", stderr)
		}
	})

	t.Run("--clock-skew widens the window", func(t *testing.T) {
		recent := encodePasetoLocal(t,
			"--key", pasetoTestKey,
			"--payload", expiredPasetoPayload(time.Minute),
		)

		cmd := createPasetoDecodeLocalCommand()
		registerPasetoDecodeFlags(cmd)
		out, err := executeCommand(cmd,
			"--key", pasetoTestKey,
			"--token", recent,
			"--validate-claims",
			"--clock-skew", "5m",
		)
		if err != nil {
			t.Fatalf("Expected the token to decode inside the tolerance, got: %v", err)
		}
		if !strings.Contains(out, "John Doe") {
			t.Errorf("Expected claims in output, got: %s", out)
		}
	})
}
