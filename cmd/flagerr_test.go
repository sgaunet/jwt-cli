package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestMisplacedFlagNamesItsSubcommands covers the one usage the move to
// per-leaf flags broke: a boolean flag written before the subcommand.
//
// Cobra's stripFlags only knows a flag is boolean at the level where it is
// declared, so "encode --allow-weak-secret hs256" reads hs256 as the flag's
// value and parses the flag against encode, which does not declare it. The
// position requirement is not fixable from here, but "unknown flag" alone is a
// misleading way to report a flag that exists one word further right.
func TestMisplacedFlagNamesItsSubcommands(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		flag    string
		accepts []string
		example string
	}{
		{
			name:    "encode with --allow-weak-secret before the algorithm",
			args:    []string{"encode", "--allow-weak-secret", "hs256"},
			flag:    "--allow-weak-secret",
			accepts: []string{"hs256", "hs384", "hs512"},
			example: "jwt-cli encode hs256 --allow-weak-secret",
		},
		{
			name: "encode with --allow-weak-key before the algorithm names only RSA",
			args: []string{"encode", "--allow-weak-key", "rs256"},
			flag: "--allow-weak-key",
			// The ES commands do not declare the flag, so they must not be
			// offered as a place to move it to.
			accepts: []string{"rs256", "rs384", "rs512"},
			example: "jwt-cli encode rs256 --allow-weak-key",
		},
		{
			name:    "decode with --validate-claims before the algorithm",
			args:    []string{"decode", "--validate-claims", "hs256"},
			flag:    "--validate-claims",
			accepts: []string{"es256", "hs256", "rs256"},
			example: "jwt-cli decode es256 --validate-claims",
		},
		{
			name:    "paseto decode with --validate-claims before the purpose",
			args:    []string{"paseto", "decode", "--validate-claims", "local"},
			flag:    "--validate-claims",
			accepts: []string{"local", "public"},
			example: "jwt-cli paseto decode local --validate-claims",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executeRoot(t, tt.args...)
			if err == nil {
				t.Fatalf("%v should fail, got no error", tt.args)
			}
			msg := err.Error()
			// The original pflag report is kept: it is the line that names what
			// the shell actually rejected.
			if !strings.Contains(msg, "unknown flag: "+tt.flag) {
				t.Errorf("%v should still report the unknown flag, got: %v", tt.args, msg)
			}
			for _, accepted := range tt.accepts {
				if !strings.Contains(msg, accepted) {
					t.Errorf("%v should name %s as accepting %s, got: %v",
						tt.args, accepted, tt.flag, msg)
				}
			}
			if !strings.Contains(msg, tt.example) {
				t.Errorf("%v should show %q as the corrected form, got: %v",
					tt.args, tt.example, msg)
			}
		})
	}
}

// TestMisplacedFlagHintOnlyForRealFlags pins that the hint is not attached to
// every unknown flag. A flag no subcommand declares - a typo, or the ES
// commands' deliberate refusal of --allow-weak-key - has nowhere to be moved to,
// so inventing a position for it would be worse than the bare report.
func TestMisplacedFlagHintOnlyForRealFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		flag string
	}{
		{"typo on a group", []string{"encode", "--no-such-flag", "hs256"}, "--no-such-flag"},
		{"typo on a leaf", []string{"encode", "hs256", "--no-such-flag"}, "--no-such-flag"},
		{
			// ECDSA key size is fixed by the curve the algorithm names, so the
			// ES commands leave --allow-weak-key unregistered on purpose.
			"--allow-weak-key on an ES leaf",
			[]string{"encode", "es256", "--allow-weak-key"},
			"--allow-weak-key",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executeRoot(t, tt.args...)
			if err == nil {
				t.Fatalf("%v should fail, got no error", tt.args)
			}
			msg := err.Error()
			if !strings.Contains(msg, "unknown flag: "+tt.flag) {
				t.Errorf("%v should report the unknown flag, got: %v", tt.args, msg)
			}
			if strings.Contains(msg, "accepted by:") {
				t.Errorf("%v should carry no move-it hint, got: %v", tt.args, msg)
			}
		})
	}
}

// TestSubcommandsDeclaringStopsAtNearestDepth pins that the hint names the level
// the flag has to follow rather than every command below it. --validate-claims is
// declared by "paseto decode local", two levels under paseto; asked from paseto
// the answer is the "decode" level, not the leaves.
func TestSubcommandsDeclaringStopsAtNearestDepth(t *testing.T) {
	owners, flag := subcommandsDeclaring(pasetoCmd, flagValidateClaims)

	if flag != flagValidateClaims {
		t.Errorf("expected flag %q, got %q", flagValidateClaims, flag)
	}
	want := []string{"decode local", "decode public"}
	if len(owners) != len(want) {
		t.Fatalf("expected %v, got %v", want, owners)
	}
	for i, name := range want {
		if owners[i] != name {
			t.Errorf("owner %d: expected %q, got %q", i, name, owners[i])
		}
	}
}

// TestMisplacedFlagNeverOffersADeprecatedAlias covers the trap in resolving the
// name pflag rejected: the deprecated long aliases are single letters, the same
// shape a rejected shorthand arrives in. A bare Lookup of "p" therefore finds
// "--p" - deprecated since it was replaced by --payload/-p - so an unresolved
// hint would answer a mistyped "-p" with "use --p", both the wrong dash form and
// a flag on its way out.
func TestMisplacedFlagNeverOffersADeprecatedAlias(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		// -p before the algorithm swallows it as the payload value, leaving no
		// subcommand, so the flag is parsed against the group and rejected.
		{"shorthand with no value", []string{"encode", "-p", "hs256"}},
		{"deprecated alias with no value", []string{"encode", "--p", "hs256"}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executeRoot(t, tt.args...)
			if err == nil {
				t.Fatalf("%v should fail, got no error", tt.args)
			}
			msg := err.Error()
			// Assert on the hint alone. The pflag line above it echoes what the
			// user actually typed, "--p" included, and must keep doing so.
			_, hint, found := strings.Cut(msg, "\n\n")
			if !found || !strings.Contains(hint, "accepted by:") {
				t.Fatalf("%v should carry the move-it hint, got: %v", tt.args, msg)
			}
			// The hint must name the live flag, --payload, and must not tell the
			// user to write the retired alias.
			if !strings.Contains(hint, "jwt-cli encode es256 --payload ...") {
				t.Errorf("%v should offer --payload, got: %v", tt.args, hint)
			}
			if strings.Contains(hint, "--p ") || strings.Contains(hint, "--p\n") {
				t.Errorf("%v should not offer the deprecated --p alias, got: %v", tt.args, hint)
			}
		})
	}
}

// TestCanonicalFlagNameResolvesShorthand pins the resolution directly, since the
// end-to-end cases above can only reach it through a flag that happens to have
// both a shorthand and a retired alias.
func TestCanonicalFlagNameResolvesShorthand(t *testing.T) {
	cases := []struct {
		name  string
		cmd   *cobra.Command
		given string
		want  string
		ok    bool
	}{
		// The long name of a live flag resolves to itself.
		{"long name", encodeES256Cmd, flagPayload, flagPayload, true},
		// "p" is both --payload's shorthand and the retired --p alias. The
		// shorthand's flag has to win.
		{"shorthand letter", encodeES256Cmd, aliasPayload, flagPayload, true},
		{"typo", encodeES256Cmd, "no-such-flag", "", false},
		// The weak-key and weak-secret opt-outs are family-scoped: each is a
		// match on its own family and a miss everywhere else.
		{"weak secret on HMAC", encodeHS256Cmd, flagAllowWeakSecret, flagAllowWeakSecret, true},
		{"weak secret on ECDSA", encodeES256Cmd, flagAllowWeakSecret, "", false},
		{"weak key on RSA", encodeRS256Cmd, flagAllowWeakKey, flagAllowWeakKey, true},
		{"weak key on ECDSA", encodeES256Cmd, flagAllowWeakKey, "", false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := canonicalFlagName(tt.cmd, tt.given)
			if ok != tt.ok {
				t.Fatalf("%s %q: expected ok=%v, got %v (%q)",
					tt.cmd.Name(), tt.given, tt.ok, ok, got)
			}
			if got != tt.want {
				t.Errorf("%s %q: expected %q, got %q",
					tt.cmd.Name(), tt.given, tt.want, got)
			}
		})
	}
}
