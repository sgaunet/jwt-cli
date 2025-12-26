package cmd

import (
	"strings"
	"testing"
)

// TestVersionCommand_Output tests that version command produces output
func TestVersionCommand_Output(t *testing.T) {
	output, err := executeCommand(versionCmd)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	outputStr := strings.TrimSpace(output)
	if outputStr == "" {
		t.Error("Expected version output, got empty string")
	}

	// Version output should contain version information
	if !strings.Contains(outputStr, "version") && !strings.Contains(outputStr, "dev") {
		t.Logf("Version output: %s", outputStr)
	}
}
