package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestInvalidSubcommandExitsNonZero is the regression test for the worst of the
// findings: "jwt-cli encode hs257" printed help and exited 0, so a scripted
// "cmd || exit 1" passed while verifying nothing.
//
// Cobra checks Runnable() before it validates positional arguments, so a group
// command with no RunE short-circuits to help text plus a nil error. Every group
// therefore has both a RunE and an Args validator now.
func TestInvalidSubcommandExitsNonZero(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"encode with a mistyped algorithm", []string{"encode", "hs257"}},
		{"decode with a mistyped algorithm", []string{"decode", "hs257"}},
		{"genkeys with an unknown algorithm", []string{"genkeys", "bogus"}},
		{"paseto with an unknown verb", []string{"paseto", "bogus"}},
		{"paseto encode with an unknown purpose", []string{"paseto", "encode", "bogus"}},
		{"paseto decode with an unknown purpose", []string{"paseto", "decode", "bogus"}},
		{"paseto genkeys with an unknown version", []string{"paseto", "genkeys", "v9"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executeRoot(t, tt.args...)
			if err == nil {
				t.Fatalf("%v should fail, got no error", tt.args)
			}
			if !strings.Contains(err.Error(), "invalid argument") {
				t.Errorf("%v should report an invalid argument, got: %v", tt.args, err)
			}
		})
	}
}

// TestBareGroupPrintsHelp pins that naming no subcommand stays a help-and-exit-0
// case. A bare group is how the algorithms are discovered, so it is not an
// error; only a word that matches no subcommand is.
func TestBareGroupPrintsHelp(t *testing.T) {
	groups := [][]string{
		{"encode"},
		{"decode"},
		{"genkeys"},
		{"paseto"},
		{"paseto", "encode"},
		{"paseto", "decode"},
		{"paseto", "genkeys"},
	}

	for _, args := range groups {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			output, err := executeRoot(t, args...)
			if err != nil {
				t.Fatalf("%v should print help and succeed, got: %v", args, err)
			}
			if !strings.Contains(output, "Available Commands:") {
				t.Errorf("%v should print help listing its subcommands, got: %s", args, output)
			}
		})
	}
}

// TestUnknownTopLevelCommandStillErrors guards the corollary of the fix: rootCmd
// must keep its nil Args, because Cobra only applies its unknown-command
// handling when the command it found has no Args validator. Setting one on root
// would turn "jwt-cli bogus" back into help plus exit 0.
func TestUnknownTopLevelCommandStillErrors(t *testing.T) {
	for _, arg := range []string{"bogus", "deocde"} {
		t.Run(arg, func(t *testing.T) {
			_, err := executeRoot(t, arg)
			if err == nil {
				t.Fatalf("%q should fail, got no error", arg)
			}
			if !strings.Contains(err.Error(), "unknown command") {
				t.Errorf("%q should report an unknown command, got: %v", arg, err)
			}
		})
	}
}

// TestTrailingPositionalArgumentRejected pins cobra.NoArgs on the leaves. A
// trailing word used to be accepted and ignored.
func TestTrailingPositionalArgumentRejected(t *testing.T) {
	cases := [][]string{
		{"encode", "hs256", "--payload", validPayload, "--secret", hs256Secret, "extra"},
		{"decode", "hs256", "--token", "irrelevant", "--secret", hs256Secret, "extra"},
		{"version", "extra"},
	}

	for _, args := range cases {
		t.Run(strings.Join(args[:2], " "), func(t *testing.T) {
			_, err := executeRoot(t, args...)
			if err == nil {
				t.Fatalf("%v should fail, got no error", args)
			}
			if !strings.Contains(err.Error(), "unknown command") {
				t.Errorf("%v should report an unknown command, got: %v", args, err)
			}
		})
	}
}

// TestCrossFamilyFlagRejected pins the per-leaf flag registration end to end,
// through the real command tree rather than a detached command.
func TestCrossFamilyFlagRejected(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"HMAC encode rejects --private-key", []string{
			"encode", "hs256", "--payload", validPayload, "--secret", hs256Secret,
			"--private-key", "/dev/null",
		}},
		{"RSA encode rejects --allow-weak-secret", []string{
			"encode", "rs256", "--payload", validPayload, "--private-key", "/dev/null",
			"--allow-weak-secret",
		}},
		{"ECDSA encode rejects --allow-weak-key", []string{
			"encode", "es256", "--payload", validPayload, "--private-key", "/dev/null",
			"--allow-weak-key",
		}},
		{"HMAC encode rejects --validate-claims", []string{
			"encode", "hs256", "--payload", validPayload, "--secret", hs256Secret,
			"--validate-claims",
		}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executeRoot(t, tt.args...)
			if err == nil {
				t.Fatalf("%v should fail, got no error", tt.args)
			}
			if !strings.Contains(err.Error(), "unknown flag") {
				t.Errorf("%v should report an unknown flag, got: %v", tt.args, err)
			}
		})
	}
}

// TestInvalidSubcommandRendersJSONEnvelope pins that the failure reaches
// output(), so --json mode gets a machine-readable envelope on stdout instead of
// help text. Previously "jwt-cli --json encode hs257" put help on stdout and
// exited 0, breaking the one mode built for scripts.
//
// Execute() is what renders an error Cobra returned, and it calls os.Exit, so
// this drives the same two steps directly: run the tree, then report.
func TestInvalidSubcommandRendersJSONEnvelope(t *testing.T) {
	_, err := executeRoot(t, "encode", "hs257")
	if err == nil {
		t.Fatal("expected an error for a mistyped algorithm")
	}

	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })

	rendered := captureStdout(t, func() { reportError(err) })

	var envelope struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if jsonErr := json.Unmarshal([]byte(rendered), &envelope); jsonErr != nil {
		t.Fatalf("--json output should be valid JSON, got %q: %v", rendered, jsonErr)
	}
	if envelope.Success {
		t.Error("envelope should report success=false")
	}
	if !strings.Contains(envelope.Error, `invalid argument "hs257"`) {
		t.Errorf("envelope should name the bad argument, got: %q", envelope.Error)
	}
}
