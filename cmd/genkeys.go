package cmd

import (
	"github.com/spf13/cobra"
)

// genkeysCmd represents the genkeys command.
var genkeysCmd = &cobra.Command{
	Use:   "genkeys <algorithm>",
	Short: "Print commands to generate cryptographic keys",
	Long: `Print example commands to generate cryptographic key pairs for RSA and ECDSA algorithms.

These commands use OpenSSL to generate properly formatted keys for JWT signing.
The generated keys can be used with jwt-cli's encode and decode commands.

Available algorithms:
  - RSA: RS256, RS384, RS512 (4096-bit keys)
  - ECDSA: ES256, ES384, ES512 (P-256, P-384, P-521 curves)`,
	Example: `  # Show commands for RS256 key generation
  jwt-cli genkeys rs256

  # Show commands for ES256 key generation
  jwt-cli genkeys es256

  # Generate keys by running the output
  $(jwt-cli genkeys rs256)`,
	ValidArgs: jwtAlgorithms,
}

// genkeysRecipeOutput is the --json shape of a JWT key-generation recipe.
type genkeysRecipeOutput struct {
	// Algorithm is the algorithm the commands generate keys for, e.g. "rs256".
	Algorithm string `json:"algorithm"`
	// Commands are the shell commands to run, in order.
	Commands []string `json:"commands"`
}

// createGenkeysCommand builds a genkeys subcommand that prints the shell
// commands generating a key pair for one algorithm.
//
// The commands are data rather than inline prints so that --json can emit them
// as a list. The plain-text form stays exactly these lines, in order, because
// callers eval it.
func createGenkeysCommand(use, short, long, example string, commands []string) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		Args:    cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			outputRecipe(genkeysRecipeOutput{Algorithm: use, Commands: commands}, commands)
		},
	}
}

var genkeysES256Cmd = createGenkeysCommand(
	"es256",
	"Print commands to generate ES256 (P-256) keys",
	`Print OpenSSL commands to generate ECDSA key pair using P-256 curve for ES256 algorithm.

The generated keys will be in PEM format:
  - ES256-private.pem: Private key for signing
  - ES256-public.pem: Public key for verification`,
	`  # Show the commands
  jwt-cli genkeys es256

  # Execute the commands directly
  $(jwt-cli genkeys es256)`,
	[]string{
		"openssl ecparam -genkey -name prime256v1  -noout -out ES256-private.pem",
		"openssl ec -in ES256-private.pem -pubout -out ES256-public.pem",
	},
)

var genkeysES384Cmd = createGenkeysCommand(
	"es384",
	"Print commands to generate ES384 (P-384) keys",
	`Print OpenSSL commands to generate ECDSA key pair using P-384 curve for ES384 algorithm.

The generated keys will be in PEM format:
  - ES384-private.pem: Private key for signing
  - ES384-public.pem: Public key for verification`,
	`  # Show the commands
  jwt-cli genkeys es384

  # Execute the commands directly
  $(jwt-cli genkeys es384)`,
	[]string{
		"openssl ecparam -name secp384r1 -genkey -noout -out ES384-private.pem",
		"openssl ec -in ES384-private.pem -pubout -out ES384-public.pem",
	},
)

var genkeysES512Cmd = createGenkeysCommand(
	"es512",
	"Print commands to generate ES512 (P-521) keys",
	`Print OpenSSL commands to generate ECDSA key pair using P-521 curve for ES512 algorithm.

The generated keys will be in PEM format:
  - ES512-private.pem: Private key for signing
  - ES512-public.pem: Public key for verification`,
	`  # Show the commands
  jwt-cli genkeys es512

  # Execute the commands directly
  $(jwt-cli genkeys es512)`,
	[]string{
		"openssl ecparam -genkey -name secp521r1 -noout -out ES512-private.pem",
		"openssl ec -in ES512-private.pem -pubout -out ES512-public.pem",
	},
)

var genkeysRS256Cmd = createGenkeysCommand(
	"rs256",
	"Print commands to generate RS256 (RSA 4096-bit) keys",
	`Print commands to generate RSA key pair (4096-bit) for RS256 algorithm.

The generated keys will be in PEM format:
  - RS256-private.pem: Private key for signing
  - RS256-public.pem: Public key for verification`,
	`  # Show the commands
  jwt-cli genkeys rs256

  # Execute the commands directly
  $(jwt-cli genkeys rs256)`,
	[]string{
		"ssh-keygen -t rsa -b 4096 -E SHA256 -m PEM -P '' -f RS256-private.pem",
		"openssl rsa -in RS256-private.pem -pubout -outform PEM -out RS256-public.pem",
	},
)

var genkeysRS384Cmd = createGenkeysCommand(
	"rs384",
	"Print commands to generate RS384 (RSA 4096-bit) keys",
	`Print commands to generate RSA key pair (4096-bit) for RS384 algorithm.

The generated keys will be in PEM format:
  - RS384-private.pem: Private key for signing
  - RS384-public.pem: Public key for verification`,
	`  # Show the commands
  jwt-cli genkeys rs384

  # Execute the commands directly
  $(jwt-cli genkeys rs384)`,
	[]string{
		"ssh-keygen -t rsa -b 4096 -E SHA384 -m PEM -P '' -f RS384-private.pem",
		"openssl rsa -in RS384-private.pem -pubout -outform PEM -out RS384-public.pem",
	},
)

var genkeysRS512Cmd = createGenkeysCommand(
	"rs512",
	"Print commands to generate RS512 (RSA 4096-bit) keys",
	`Print commands to generate RSA key pair (4096-bit) for RS512 algorithm.

The generated keys will be in PEM format:
  - RS512-private.pem: Private key for signing
  - RS512-public.pem: Public key for verification`,
	`  # Show the commands
  jwt-cli genkeys rs512

  # Execute the commands directly
  $(jwt-cli genkeys rs512)`,
	[]string{
		"ssh-keygen -t rsa -b 4096 -E SHA512 -m PEM -P '' -f RS512-private.pem",
		"openssl rsa -in RS512-private.pem -pubout -outform PEM -out RS512-public.pem",
	},
)
