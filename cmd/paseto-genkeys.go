package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// pasetoKeyRecipe holds the two commands that generate one version's key pair.
//
// The commands are kept apart from the "#" commentary that surrounds them in the
// printed recipe, so that --json can emit the commands alone: a machine consumer
// wants what to run, not the annotations.
type pasetoKeyRecipe struct {
	// privateKeyCommand generates the private key.
	privateKeyCommand string
	// publicKeyCommand extracts the matching public key.
	publicKeyCommand string
}

// pasetoRecipeOutput is the --json shape of a PASETO key-generation recipe.
type pasetoRecipeOutput struct {
	// Version is the PASETO version the keys are for, e.g. "v4".
	Version string `json:"version"`
	// KeyType names the key pair's algorithm, e.g. "Ed25519".
	KeyType string `json:"key_type"`
	// LocalKeyCommand generates the symmetric key local tokens use.
	LocalKeyCommand string `json:"local_key_command"`
	// PublicKeyCommands generate the key pair public tokens use, in order.
	PublicKeyCommands []string `json:"public_key_commands"`
}

// pasetoLocalKeyCommand generates the symmetric key that local tokens use. It is
// the same for every version.
const pasetoLocalKeyCommand = "openssl rand -hex 32"

// pasetoRecipeLines renders the printed recipe: commentary interleaved with the
// commands, exactly as it has always been emitted.
//
// The integration suite runs
// eval "$(jwt-cli paseto genkeys v3 | grep '^openssl' | tail -2)", so both the
// content and the ordering of these lines are a compatibility surface - the two
// key-pair commands must stay the last two lines starting with "openssl".
func pasetoRecipeLines(version, keyType string, recipe pasetoKeyRecipe) []string {
	return []string{
		fmt.Sprintf("# PASETO %s Key Generation", version),
		"",
		"# Generate local (symmetric) key (32 bytes)",
		pasetoLocalKeyCommand,
		"",
		fmt.Sprintf("# Generate public (asymmetric) key pair (%s)", keyType),
		"# Generate private key",
		recipe.privateKeyCommand,
		"# Extract public key",
		recipe.publicKeyCommand,
	}
}

// createPasetoGenkeysCommand builds a "paseto genkeys <version>" command that
// prints the OpenSSL recipe for that version's keys.
//
// It is a factory rather than a package-level literal so that tests can execute
// a detached instance: calling Execute on a command already attached to the
// root would run the root command instead.
func createPasetoGenkeysCommand(version, keyType, long string, recipe pasetoKeyRecipe) *cobra.Command {
	return &cobra.Command{
		Use:   version,
		Short: fmt.Sprintf("Print commands to generate PASETO %s keys", version),
		Long:  long,
		Example: fmt.Sprintf(`  # Show the commands
  jwt-cli paseto genkeys %s

  # Execute the commands directly
  $(jwt-cli paseto genkeys %s)`, version, version),
		Args: cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			outputRecipe(pasetoRecipeOutput{
				Version:           version,
				KeyType:           keyType,
				LocalKeyCommand:   pasetoLocalKeyCommand,
				PublicKeyCommands: []string{recipe.privateKeyCommand, recipe.publicKeyCommand},
			}, pasetoRecipeLines(version, keyType, recipe))
		},
	}
}

// ed25519GenkeysLong builds the long help shared by the Ed25519 versions.
func ed25519GenkeysLong(version string) string {
	return fmt.Sprintf(`Print OpenSSL commands to generate keys for PASETO %s tokens.

Local tokens use a hex-encoded 32-byte symmetric key.
Public tokens use an Ed25519 key pair in PEM format:
  - paseto-%s-private.pem: private key for signing
  - paseto-%s-public.pem:  public key for verification`, version, version, version)
}

// ed25519GenkeysRecipe builds the OpenSSL commands for an Ed25519 key pair.
func ed25519GenkeysRecipe(version string) pasetoKeyRecipe {
	return pasetoKeyRecipe{
		privateKeyCommand: fmt.Sprintf(
			"openssl genpkey -algorithm Ed25519 -out paseto-%s-private.pem", version),
		publicKeyCommand: fmt.Sprintf(
			"openssl pkey -in paseto-%s-private.pem -pubout -out paseto-%s-public.pem", version, version),
	}
}

var pasetoGenkeysV4Cmd = createPasetoGenkeysCommand(
	pasetoV4, "Ed25519", ed25519GenkeysLong(pasetoV4), ed25519GenkeysRecipe(pasetoV4))

var pasetoGenkeysV2Cmd = createPasetoGenkeysCommand(
	pasetoV2, "Ed25519", ed25519GenkeysLong(pasetoV2), ed25519GenkeysRecipe(pasetoV2))

var pasetoGenkeysV3Cmd = createPasetoGenkeysCommand(
	pasetoV3, "P-384",
	`Print OpenSSL commands to generate keys for PASETO v3 tokens.

Local tokens use a hex-encoded 32-byte symmetric key.
Public tokens use a NIST P-384 key pair in PEM format:
  - paseto-v3-private.pem: private key for signing
  - paseto-v3-public.pem:  public key for verification

Both the SEC 1 encoding shown below and the PKCS#8 encoding produced by
"openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384" are accepted.`,
	pasetoKeyRecipe{
		privateKeyCommand: "openssl ecparam -genkey -name secp384r1 -noout -out paseto-v3-private.pem",
		publicKeyCommand:  "openssl ec -in paseto-v3-private.pem -pubout -out paseto-v3-public.pem",
	})
