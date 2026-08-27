package cmd

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

// TestValidationErrorsAreReported checks that the JWT missing-flag errors reach
// the user. rootCmd sets SilenceErrors, so an error merely returned from RunE
// exits 1 without printing anything: every failure has to go through
// userError/userErrorf so output() renders it.
func TestValidationErrorsAreReported(t *testing.T) {
	tests := []struct {
		name string
		// build returns a fresh command plus the args to run it with.
		build func(t *testing.T) (*cobra.Command, []string)
		want  string
	}{
		{
			name: "hs256 encode without secret",
			build: func(_ *testing.T) (*cobra.Command, []string) {
				cmd := createHSEncodeCommand("HS256", "hs256", "Test", "Test", "Test",
					cryptojwt.NewHS256EncoderWithOptions)
				return cmd, []string{"--payload", validPayload}
			},
			want: "secret is required",
		},
		{
			name: "hs256 encode without payload",
			build: func(_ *testing.T) (*cobra.Command, []string) {
				cmd := createHSEncodeCommand("HS256", "hs256", "Test", "Test", "Test",
					cryptojwt.NewHS256EncoderWithOptions)
				return cmd, []string{"--secret", hs256Secret}
			},
			want: "payload is required",
		},
		{
			name: "hs256 decode without secret",
			build: func(_ *testing.T) (*cobra.Command, []string) {
				cmd := createHSDecodeCommand("HS256", "hs256", "Test", "Test", "Test",
					cryptojwt.NewHS256DecoderWithValidation)
				return cmd, []string{"--token", "header.payload.signature"}
			},
			want: "secret is required",
		},
		{
			name: "hs256 decode without token",
			build: func(_ *testing.T) (*cobra.Command, []string) {
				cmd := createHSDecodeCommand("HS256", "hs256", "Test", "Test", "Test",
					cryptojwt.NewHS256DecoderWithValidation)
				return cmd, []string{"--secret", hs256Secret}
			},
			want: "token is required",
		},
		{
			name: "rs256 encode without private key",
			build: func(_ *testing.T) (*cobra.Command, []string) {
				cmd := createAsymmetricEncodeCommand(rsKeyVocab, "rs256", "Test", "Test", "Test",
					cryptojwt.NewRS256EncoderWithOptions)
				return cmd, []string{"--payload", validPayload}
			},
			want: "private key file is required",
		},
		{
			name: "rs256 decode without keys",
			build: func(_ *testing.T) (*cobra.Command, []string) {
				cmd := createAsymmetricDecodeCommand(rsKeyVocab, "rs256", "Test", "Test", "Test",
					cryptojwt.NewRS256DecoderWithPublicKeyFileAndOptions,
					cryptojwt.NewRS256DecoderWithPrivateKeyFileAndOptions)
				return cmd, []string{"--token", "header.payload.signature"}
			},
			want: "key file is required",
		},
		{
			name: "es256 encode without private key",
			build: func(_ *testing.T) (*cobra.Command, []string) {
				cmd := createAsymmetricEncodeCommand(esKeyVocab, "es256", "Test", "Test", "Test",
					ignoreWeakKeyEncoder(cryptojwt.NewES256Encoder))
				return cmd, []string{"--payload", validPayload}
			},
			want: "private key file is required",
		},
		{
			name: "es256 decode without token",
			build: func(t *testing.T) (*cobra.Command, []string) {
				t.Helper()
				_, publicKey := generateECDSAKeyPair(t, elliptic.P256())
				cmd := createAsymmetricDecodeCommand(esKeyVocab, "es256", "Test", "Test", "Test",
					ignoreWeakKeyDecoder(cryptojwt.NewES256DecoderWithPublicKeyFileAndValidation),
					ignoreWeakKeyDecoder(cryptojwt.NewES256DecoderWithPrivateKeyFileAndValidation))
				return cmd, []string{"--public-key", publicKey}
			},
			want: "token is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args := tt.build(t)

			var err error
			stderr := captureStderr(t, func() {
				_, err = executeCommand(cmd, args...)
			})

			if err == nil {
				t.Fatalf("Expected an error, got nil")
			}
			if !strings.Contains(stderr, tt.want) {
				t.Errorf("Expected stderr to contain %q, got: %q", tt.want, stderr)
			}
		})
	}
}

// TestValidationErrorJSONOutput checks that a missing-flag failure still emits a
// JSON failure envelope when --json is set.
func TestValidationErrorJSONOutput(t *testing.T) {
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })

	cmd := createHSEncodeCommand("HS256", "hs256", "Test", "Test", "Test",
		cryptojwt.NewHS256EncoderWithOptions)

	out, err := executeCommand(cmd, "--payload", validPayload)
	if err == nil {
		t.Fatal("Expected an error for missing secret, got nil")
	}
	if !strings.Contains(out, `"success": false`) {
		t.Errorf("Expected a JSON failure envelope, got: %q", out)
	}
	if !strings.Contains(out, "secret is required") {
		t.Errorf("Expected the JSON envelope to carry the error message, got: %q", out)
	}
}

// TestReportErrorPrintsUnreportedError checks that Cobra's own errors - flag
// parse failures, unknown commands - are printed by Execute() instead of being
// swallowed by SilenceErrors.
func TestReportErrorPrintsUnreportedError(t *testing.T) {
	stderr := captureStderr(t, func() {
		reportError(errors.New("unknown flag: --bogus"))
	})

	if !strings.Contains(stderr, "unknown flag: --bogus") {
		t.Errorf("Expected reportError to print the error, got: %q", stderr)
	}
}

// TestReportErrorSkipsReportedError guards against double-printing: userError
// has already rendered its message through output(), so reportError must stay
// quiet.
func TestReportErrorSkipsReportedError(t *testing.T) {
	var reported error
	firstPrint := captureStderr(t, func() {
		reported = userError("encoding failed: boom")
	})
	if !strings.Contains(firstPrint, "encoding failed: boom") {
		t.Fatalf("Expected userError to print the message, got: %q", firstPrint)
	}

	secondPrint := captureStderr(t, func() {
		reportError(reported)
	})
	if secondPrint != "" {
		t.Errorf("Expected reportError to skip an already-reported error, got: %q", secondPrint)
	}
}

// TestReportErrorSkipsWrappedReportedError checks the sentinel survives
// wrapping, since Cobra may wrap the error a command returned.
func TestReportErrorSkipsWrappedReportedError(t *testing.T) {
	var wrapped error
	// Build the error inside a capture too: userError prints as it is created.
	_ = captureStderr(t, func() {
		wrapped = fmt.Errorf("command execution failed: %w", userError("decoding failed: boom"))
	})

	stderr := captureStderr(t, func() {
		reportError(wrapped)
	})
	if stderr != "" {
		t.Errorf("Expected reportError to skip a wrapped reported error, got: %q", stderr)
	}
}
