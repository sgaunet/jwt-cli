package cmd

import (
	"encoding/json"
	"fmt"
	"os"
)

// CommandOutput represents the structured output format for all commands.
// It provides a consistent interface for both JSON and human-readable output modes.
type CommandOutput struct {
	// Success indicates whether the operation completed successfully
	Success bool `json:"success"`

	// Data holds generic output data (rarely used, reserved for future extensions)
	Data any `json:"data,omitempty"`

	// Claims holds the decoded JWT claims/payload
	Claims any `json:"claims,omitempty"`

	// Token holds the encoded JWT token string
	Token string `json:"token,omitempty"`

	// Error holds the error message if Success is false
	Error string `json:"error,omitempty"`
}

// output writes the command result to stdout in either JSON or human-readable format.
// In JSON mode, it always outputs valid JSON regardless of success/failure.
// In human-readable mode, errors are written to stderr.
// Note: This function does NOT call os.Exit(). Exit handling is done by the caller
// through Cobra's error return mechanism and root.Execute().
func output(out CommandOutput) {
	if jsonOutput {
		outputJSON(out)
		return
	}
	outputHumanReadable(out)
}

// outputJSON writes the output in JSON format.
func outputJSON(out CommandOutput) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		// This should never happen, but if JSON encoding fails, output a minimal error
		fmt.Fprintf(os.Stderr, `{"success":false,"error":"failed to encode JSON output: %s"}`+"\n", err)
	}
}

// outputHumanReadable writes the output in human-readable format.
func outputHumanReadable(out CommandOutput) {
	if out.Error != "" {
		fmt.Fprintln(os.Stderr, out.Error)
		return
	}
	if out.Token != "" {
		fmt.Println(out.Token)
	}
	if out.Claims != nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out.Claims); err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode claims: %s\n", err)
		}
	}
}
