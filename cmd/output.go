package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
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

// jsonFlagArg is the long form of --json as it appears in os.Args.
const jsonFlagArg = "--json"

// wantsJSONOutput reports whether raw arguments ask for JSON output.
//
// Cobra abandons a command at the first flag it cannot parse, and reports an
// unknown command before binding any flag at all, so in those cases --json never
// reaches jsonOutput and a failure would be rendered as plain text - breaking
// the promise output() makes. Execute() consults this on the failure path to
// recover the intent from the arguments themselves.
//
// pflag's rules are mirrored: "--" ends flag parsing, and the last occurrence
// wins. An unparseable value is ignored, since Cobra reports that itself.
func wantsJSONOutput(args []string) bool {
	want := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == jsonFlagArg {
			want = true
			continue
		}
		if value, ok := strings.CutPrefix(arg, jsonFlagArg+"="); ok {
			if parsed, err := strconv.ParseBool(value); err == nil {
				want = parsed
			}
		}
	}
	return want
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

// reportedError marks an error whose message output() has already rendered, so
// Execute() does not print it a second time.
type reportedError struct {
	msg string
}

// Error returns the message that was already reported to the user.
func (e *reportedError) Error() string {
	return e.msg
}

// userError reports a user-facing failure through output() and returns it so
// Cobra exits non-zero.
//
// Every command failure is routed through output(): rootCmd sets SilenceErrors,
// so an error merely returned from RunE would exit 1 without printing anything,
// and only output() renders the --json failure envelope.
func userError(msg string) error {
	output(CommandOutput{Success: false, Error: msg})
	return &reportedError{msg: msg}
}

// userErrorf is userError with printf-style formatting.
func userErrorf(format string, a ...any) error {
	return userError(fmt.Sprintf(format, a...))
}

// reportError prints an error that no command has rendered yet, such as Cobra's
// own flag-parse and unknown-command errors. Errors produced by userError are
// skipped, since their message has already been printed.
func reportError(err error) {
	var reported *reportedError
	if errors.As(err, &reported) {
		return
	}
	output(CommandOutput{Success: false, Error: err.Error()})
}

// outputToken emits a freshly encoded token, honouring --json.
func outputToken(token string) {
	output(CommandOutput{Success: true, Token: token})
}

// outputClaims emits decoded claims, honouring --json.
func outputClaims(claims string) {
	// Parse claims string as JSON for structured output
	var claimsData any
	if err := json.Unmarshal([]byte(claims), &claimsData); err != nil {
		// If claims aren't valid JSON, treat as raw string
		claimsData = claims
	}
	output(CommandOutput{Success: true, Claims: claimsData})
}
