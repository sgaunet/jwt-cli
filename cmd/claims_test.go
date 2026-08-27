package cmd

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

// newHSDecodeCommandForTest builds a detached hs256 decode command.
func newHSDecodeCommandForTest() *cobra.Command {
	return createHSDecodeCommand(
		"HS256", "hs256", "Test", "Test", "Test", cryptojwt.NewHS256DecoderWithValidation)
}

// encodeHSTokenForTest signs payload with the shared hs256 test secret.
func encodeHSTokenForTest(t *testing.T, payload string) string {
	t.Helper()
	cmd := createHSEncodeCommand(
		"HS256", "hs256", "Test", "Test", "Test", cryptojwt.NewHS256EncoderWithOptions)
	token, err := executeCommand(cmd, "--payload", payload, "--secret", hs256Secret)
	if err != nil {
		t.Fatalf("Failed to encode the fixture token: %v", err)
	}
	return strings.TrimSpace(token)
}

// TestHSDecodeCommand_ClaimsValidation exercises --validate-claims and
// --clock-skew through the CLI layer.
//
// None of this could be tested here before: the register*Flags test helper
// omitted both flags even though the decode commands read them, so every
// cmd-level claims test silently ran with validation switched off. That is how
// the missing iat rule survived the suite.
func TestHSDecodeCommand_ClaimsValidation(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name      string
		payload   string
		extraArgs []string
		wantError string
	}{
		{
			name:      "expired token without --validate-claims is accepted",
			payload:   fmt.Sprintf(`{"user":"alice","exp":%d}`, now-3600),
			extraArgs: nil,
		},
		{
			name:      "expired token with --validate-claims is rejected",
			payload:   fmt.Sprintf(`{"user":"alice","exp":%d}`, now-3600),
			extraArgs: []string{"--validate-claims"},
			wantError: "token is expired",
		},
		{
			name:      "expired token inside --clock-skew is accepted",
			payload:   fmt.Sprintf(`{"user":"alice","exp":%d}`, now-60),
			extraArgs: []string{"--validate-claims", "--clock-skew", "5m"},
		},
		{
			name:      "expired token outside --clock-skew is rejected",
			payload:   fmt.Sprintf(`{"user":"alice","exp":%d}`, now-600),
			extraArgs: []string{"--validate-claims", "--clock-skew", "1m"},
			wantError: "token is expired",
		},
		{
			name:      "not-yet-valid token with --validate-claims is rejected",
			payload:   fmt.Sprintf(`{"user":"alice","nbf":%d}`, now+3600),
			extraArgs: []string{"--validate-claims"},
			wantError: "token is not valid yet",
		},
		{
			name:      "future iat with --validate-claims is rejected",
			payload:   fmt.Sprintf(`{"user":"alice","iat":%d}`, now+3600),
			extraArgs: []string{"--validate-claims"},
			wantError: "token used before issued",
		},
		{
			name:      "future iat inside --clock-skew is accepted",
			payload:   fmt.Sprintf(`{"user":"alice","iat":%d}`, now+30),
			extraArgs: []string{"--validate-claims", "--clock-skew", "5m"},
		},
		{
			name:      "valid token with --validate-claims is accepted",
			payload:   fmt.Sprintf(`{"user":"alice","exp":%d}`, now+3600),
			extraArgs: []string{"--validate-claims"},
		},
		{
			name:      "token with no time claims is accepted",
			payload:   `{"user":"alice"}`,
			extraArgs: []string{"--validate-claims"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := encodeHSTokenForTest(t, tt.payload)

			args := append([]string{"--token", token, "--secret", hs256Secret}, tt.extraArgs...)
			output, err := executeCommand(newHSDecodeCommandForTest(), args...)

			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("Expected the token to decode, got: %v", err)
				}
				if !strings.Contains(output, "alice") {
					t.Errorf("Expected the claims in the output, got: %s", output)
				}
				return
			}

			if err == nil {
				t.Fatalf("Expected the token to be rejected, got output: %s", output)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("Expected %q in the error, got: %v", tt.wantError, err)
			}
		})
	}
}

// TestHSEncodeCommand_NullPayloadRejected covers the payload that used to
// produce a token whose payload segment was the four bytes "null".
func TestHSEncodeCommand_NullPayloadRejected(t *testing.T) {
	cmd := createHSEncodeCommand(
		"HS256", "hs256", "Test", "Test", "Test", cryptojwt.NewHS256EncoderWithOptions)

	output, err := executeCommand(cmd, "--payload", "null", "--secret", hs256Secret)
	if err == nil {
		t.Fatalf("Expected a null payload to be rejected, got token: %s", output)
	}
	if !strings.Contains(err.Error(), "payload must be a JSON object") {
		t.Errorf("Expected the error to say a JSON object is required, got: %v", err)
	}
}
