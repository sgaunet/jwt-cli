package cmd

import "testing"

// TestWantsJSONOutput covers the argument sniff Execute() falls back on when a
// flag-parse or unknown-command failure means --json was never bound.
//
// It is a pure function on purpose: Execute() itself calls os.Exit, and under go
// test os.Args holds the test binary's own flags, so the sniff is the only part
// that can be tested directly.
func TestWantsJSONOutput(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"absent", []string{"encode", "hs256"}, false},
		{"no arguments at all", nil, false},
		{"bare --json", []string{"encode", "hs256", "--json"}, true},
		{"--json before the subcommand", []string{"--json", "encode", "hs256"}, true},
		{"--json=true", []string{"encode", "--json=true"}, true},
		{"--json=1", []string{"encode", "--json=1"}, true},
		{"--json=false", []string{"encode", "--json=false"}, false},
		{"last occurrence wins", []string{"--json", "encode", "--json=false"}, false},
		{"last occurrence wins the other way", []string{"--json=false", "encode", "--json"}, true},
		{"after the -- terminator", []string{"encode", "--", "--json"}, false},
		{"unparseable value is ignored", []string{"encode", "--json=bogus"}, false},
		{"a similar flag is not --json", []string{"encode", "--jsonify"}, false},

		// The accepted false positive: pflag consumes "--json" as the secret's
		// value, and the sniff still sees it. Since only the failure path reads
		// this, the cost is an error rendered as JSON when the user did not ask
		// for JSON - strictly better than a JSON-mode failure rendered as text.
		{"consumed as another flag's value", []string{"encode", "hs256", "--secret", "--json"}, true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := wantsJSONOutput(tt.args); got != tt.want {
				t.Errorf("wantsJSONOutput(%q) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
