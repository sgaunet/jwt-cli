package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestGenkeysPlainOutputIsStable pins the exact plain-text recipe of every
// genkeys command.
//
// This text is a compatibility surface, not just help: callers pipe it into a
// shell, and tests/testsuite.yml runs
// eval "$(jwt-cli paseto genkeys v3 | grep '^openssl' | tail -2)". An exact
// comparison here fails in seconds, where the integration suite would take
// minutes to notice - and would only notice for the three PASETO versions.
func TestGenkeysPlainOutputIsStable(t *testing.T) {
	cases := []struct {
		name string
		cmd  *cobra.Command
		want string
	}{
		{"es256", genkeysES256Cmd, `openssl ecparam -genkey -name prime256v1  -noout -out ES256-private.pem
openssl ec -in ES256-private.pem -pubout -out ES256-public.pem
`},
		{"es384", genkeysES384Cmd, `openssl ecparam -name secp384r1 -genkey -noout -out ES384-private.pem
openssl ec -in ES384-private.pem -pubout -out ES384-public.pem
`},
		{"es512", genkeysES512Cmd, `openssl ecparam -genkey -name secp521r1 -noout -out ES512-private.pem
openssl ec -in ES512-private.pem -pubout -out ES512-public.pem
`},
		{"rs256", genkeysRS256Cmd, `ssh-keygen -t rsa -b 4096 -E SHA256 -m PEM -P '' -f RS256-private.pem
openssl rsa -in RS256-private.pem -pubout -outform PEM -out RS256-public.pem
`},
		{"rs384", genkeysRS384Cmd, `ssh-keygen -t rsa -b 4096 -E SHA384 -m PEM -P '' -f RS384-private.pem
openssl rsa -in RS384-private.pem -pubout -outform PEM -out RS384-public.pem
`},
		{"rs512", genkeysRS512Cmd, `ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P '' -f RS512-private.pem
openssl rsa -in RS512-private.pem -pubout -outform PEM -out RS512-public.pem
`},
		{"paseto v4", pasetoGenkeysV4Cmd, `# PASETO v4 Key Generation

# Generate local (symmetric) key (32 bytes)
openssl rand -hex 32

# Generate public (asymmetric) key pair (Ed25519)
# Generate private key
openssl genpkey -algorithm Ed25519 -out paseto-v4-private.pem
# Extract public key
openssl pkey -in paseto-v4-private.pem -pubout -out paseto-v4-public.pem
`},
		{"paseto v2", pasetoGenkeysV2Cmd, `# PASETO v2 Key Generation

# Generate local (symmetric) key (32 bytes)
openssl rand -hex 32

# Generate public (asymmetric) key pair (Ed25519)
# Generate private key
openssl genpkey -algorithm Ed25519 -out paseto-v2-private.pem
# Extract public key
openssl pkey -in paseto-v2-private.pem -pubout -out paseto-v2-public.pem
`},
		{"paseto v3", pasetoGenkeysV3Cmd, `# PASETO v3 Key Generation

# Generate local (symmetric) key (32 bytes)
openssl rand -hex 32

# Generate public (asymmetric) key pair (P-384)
# Generate private key
openssl ecparam -genkey -name secp384r1 -noout -out paseto-v3-private.pem
# Extract public key
openssl ec -in paseto-v3-private.pem -pubout -out paseto-v3-public.pem
`},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := captureStdout(t, func() { tt.cmd.Run(tt.cmd, []string{}) })
			if got != tt.want {
				t.Errorf("plain recipe changed.\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestGenkeysEvalPatternStillMatches pins the shape the integration suite relies
// on: the two key-pair commands must be the last two lines beginning with
// "openssl", since that is what "grep '^openssl' | tail -2" selects.
func TestGenkeysEvalPatternStillMatches(t *testing.T) {
	cases := []struct {
		name string
		cmd  *cobra.Command
		want []string
	}{
		{"paseto v4", pasetoGenkeysV4Cmd, []string{
			"openssl genpkey -algorithm Ed25519 -out paseto-v4-private.pem",
			"openssl pkey -in paseto-v4-private.pem -pubout -out paseto-v4-public.pem",
		}},
		{"paseto v3", pasetoGenkeysV3Cmd, []string{
			"openssl ecparam -genkey -name secp384r1 -noout -out paseto-v3-private.pem",
			"openssl ec -in paseto-v3-private.pem -pubout -out paseto-v3-public.pem",
		}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(t, func() { tt.cmd.Run(tt.cmd, []string{}) })

			var opensslLines []string
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				if strings.HasPrefix(line, "openssl") {
					opensslLines = append(opensslLines, line)
				}
			}
			if len(opensslLines) < 2 {
				t.Fatalf("expected at least two openssl lines, got %d in %q", len(opensslLines), output)
			}

			got := opensslLines[len(opensslLines)-2:]
			for i, want := range tt.want {
				if got[i] != want {
					t.Errorf("last-two openssl line %d = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}

// TestGenkeysJSONOutput covers the fix for genkeys ignoring --json, which
// README's "every PASETO command supports --json" had claimed already worked.
func TestGenkeysJSONOutput(t *testing.T) {
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })

	t.Run("jwt", func(t *testing.T) {
		raw := captureStdout(t, func() { genkeysRS256Cmd.Run(genkeysRS256Cmd, []string{}) })

		var envelope struct {
			Success bool                `json:"success"`
			Data    genkeysRecipeOutput `json:"data"`
		}
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			t.Fatalf("output should be valid JSON, got %q: %v", raw, err)
		}
		if !envelope.Success {
			t.Error("envelope should report success=true")
		}
		if envelope.Data.Algorithm != "rs256" {
			t.Errorf("algorithm = %q, want rs256", envelope.Data.Algorithm)
		}
		if len(envelope.Data.Commands) != 2 {
			t.Errorf("expected two commands, got %v", envelope.Data.Commands)
		}
	})

	t.Run("paseto", func(t *testing.T) {
		raw := captureStdout(t, func() { pasetoGenkeysV3Cmd.Run(pasetoGenkeysV3Cmd, []string{}) })

		var envelope struct {
			Success bool               `json:"success"`
			Data    pasetoRecipeOutput `json:"data"`
		}
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			t.Fatalf("output should be valid JSON, got %q: %v", raw, err)
		}
		if envelope.Data.Version != pasetoV3 {
			t.Errorf("version = %q, want %s", envelope.Data.Version, pasetoV3)
		}
		if envelope.Data.KeyType != "P-384" {
			t.Errorf("key_type = %q, want P-384", envelope.Data.KeyType)
		}
		if envelope.Data.LocalKeyCommand != pasetoLocalKeyCommand {
			t.Errorf("local_key_command = %q, want %q",
				envelope.Data.LocalKeyCommand, pasetoLocalKeyCommand)
		}
		if len(envelope.Data.PublicKeyCommands) != 2 {
			t.Errorf("expected two public key commands, got %v", envelope.Data.PublicKeyCommands)
		}
		// The commentary belongs to the printed form only: a machine consumer
		// wants commands it can run.
		if strings.Contains(raw, "#") {
			t.Errorf("JSON output should carry no comment lines, got: %s", raw)
		}
	})
}
