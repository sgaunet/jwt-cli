package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestGenkeysCommands_Output tests that all genkeys commands produce expected output
func TestGenkeysCommands_Output(t *testing.T) {
	tests := []struct {
		name            string
		cmd             *cobra.Command
		expectedStrings []string
	}{
		{
			"ES256 genkeys",
			genkeysES256Cmd,
			[]string{"openssl", "ecparam", "prime256v1", "ES256"},
		},
		{
			"ES384 genkeys",
			genkeysES384Cmd,
			[]string{"openssl", "ecparam", "secp384r1", "ES384"},
		},
		{
			"ES512 genkeys",
			genkeysES512Cmd,
			[]string{"openssl", "ecparam", "secp521r1", "ES512"},
		},
		{
			"RS256 genkeys",
			genkeysRS256Cmd,
			[]string{"ssh-keygen", "rsa", "4096", "RS256"},
		},
		{
			"RS384 genkeys",
			genkeysRS384Cmd,
			[]string{"ssh-keygen", "rsa", "4096", "RS384"},
		},
		{
			"RS512 genkeys",
			genkeysRS512Cmd,
			[]string{"ssh-keygen", "rsa", "4096", "RS512"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout by redirecting it temporarily
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Call the Run function directly
			tt.cmd.Run(tt.cmd, []string{})

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r)
			outputStr := strings.TrimSpace(buf.String())

			if outputStr == "" {
				t.Fatal("Expected non-empty output")
			}

			for _, expected := range tt.expectedStrings {
				if !strings.Contains(outputStr, expected) {
					t.Errorf("Expected output to contain '%s', got: %s", expected, outputStr)
				}
			}

			// Verify output has multiple lines (private key + public key commands)
			lines := strings.Split(outputStr, "\n")
			if len(lines) < 2 {
				t.Errorf("Expected at least 2 lines of output (private + public key commands), got %d", len(lines))
			}
		})
	}
}

// TestGenkeysParentCommand_NoArgs tests parent genkeys command without algorithm
func TestGenkeysParentCommand_NoArgs(t *testing.T) {
	output, err := executeCommand(genkeysCmd)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Parent command should show help/usage
	outputStr := strings.TrimSpace(output)
	if outputStr == "" {
		t.Error("Expected usage/help output")
	}
}
