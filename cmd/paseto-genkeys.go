package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// createPasetoGenkeysCommand builds a "paseto genkeys <version>" command that
// prints the OpenSSL recipe for that version's keys.
//
// It is a factory rather than a package-level literal so that tests can execute
// a detached instance: calling Execute on a command already attached to the
// root would run the root command instead.
func createPasetoGenkeysCommand(version, keyType, long string, recipe []string) *cobra.Command {
	return &cobra.Command{
		Use:   version,
		Short: fmt.Sprintf("Print commands to generate PASETO %s keys", version),
		Long:  long,
		Example: fmt.Sprintf(`  # Show the commands
  jwt-cli paseto genkeys %s

  # Execute the commands directly
  $(jwt-cli paseto genkeys %s)`, version, version),
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("# PASETO %s Key Generation\n", version)
			fmt.Println()
			fmt.Println("# Generate local (symmetric) key (32 bytes)")
			fmt.Println("openssl rand -hex 32")
			fmt.Println()
			fmt.Printf("# Generate public (asymmetric) key pair (%s)\n", keyType)
			for _, line := range recipe {
				fmt.Println(line)
			}
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
func ed25519GenkeysRecipe(version string) []string {
	return []string{
		"# Generate private key",
		fmt.Sprintf("openssl genpkey -algorithm Ed25519 -out paseto-%s-private.pem", version),
		"# Extract public key",
		fmt.Sprintf("openssl pkey -in paseto-%s-private.pem -pubout -out paseto-%s-public.pem",
			version, version),
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
	[]string{
		"# Generate private key",
		"openssl ecparam -genkey -name secp384r1 -noout -out paseto-v3-private.pem",
		"# Extract public key",
		"openssl ec -in paseto-v3-private.pem -pubout -out paseto-v3-public.pem",
	})
