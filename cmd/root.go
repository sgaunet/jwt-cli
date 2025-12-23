package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var secret, token, payload string
var privateKeyFile, publicKeyFile string
var allowWeakSecret bool

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "jwt-cli",
	Short: "Tool to encode/decode JWT tokens",
	Long: `jwt-cli is a command-line utility for creating and validating JSON Web Tokens (JWT).

Supports multiple signing algorithms:
  - HMAC: HS256, HS384, HS512 (symmetric)
  - RSA: RS256, RS384, RS512 (asymmetric)
  - ECDSA: ES256, ES384, ES512 (asymmetric)

Use HMAC algorithms for simple use cases where both parties share a secret.
Use RSA or ECDSA for scenarios requiring public/private key pairs.`,
	Example: `  # Encode a token with HS256
  jwt-cli encode hs256 --payload '{"user":"alice"}' --secret "my-32-byte-secret-key-for-hs256"

  # Decode and verify a token
  jwt-cli decode hs256 --token "$TOKEN" --secret "my-32-byte-secret-key-for-hs256"

  # Generate keys for RSA or ECDSA
  jwt-cli genkeys rs256

  # Encode with RS256 using private key
  jwt-cli encode rs256 --payload '{"user":"alice"}' --private-key-file RS256.key`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute runs the root command.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

//nolint:funlen // init function requires many statements for command setup
func init() {
	rootCmd.AddCommand(encodeCmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = false
	encodeCmd.PersistentFlags().StringVar(&payload, "p", "", "payload")
	encodeCmd.PersistentFlags().StringVar(&privateKeyFile, "pk", "", "private key file")
	encodeCmd.PersistentFlags().StringVar(&secret, "s", "", "secret (for HMAC algorithms: HS256 requires 32+ bytes, HS384 requires 48+ bytes, HS512 requires 64+ bytes)")
	encodeCmd.PersistentFlags().BoolVar(&allowWeakSecret, "allow-weak-secret", false, "allow weak secrets for HMAC algorithms (for testing purposes only)")
	_ = encodeCmd.MarkPersistentFlagFilename("pk", "pem", "key")
	_ = encodeCmd.MarkPersistentFlagFilename("p", "json")

	// encode subcommands
	encodeCmd.AddCommand(encodeRS256Cmd)
	encodeCmd.AddCommand(encodeRS384Cmd)
	encodeCmd.AddCommand(encodeRS512Cmd)
	encodeCmd.AddCommand(encodeES256Cmd)
	encodeCmd.AddCommand(encodeES384Cmd)
	encodeCmd.AddCommand(encodeES512Cmd)
	encodeCmd.AddCommand(encodeHS256Cmd)
	encodeCmd.AddCommand(encodeHS384Cmd)
	encodeCmd.AddCommand(encodeHS512Cmd)

	rootCmd.AddCommand(decodeCmd)
	decodeCmd.PersistentFlags().StringVar(&privateKeyFile, "pk", "", "private key file")
	decodeCmd.PersistentFlags().StringVar(&publicKeyFile, "pubk", "", "public key file")
	decodeCmd.PersistentFlags().StringVar(&token, "t", "", "token")
	decodeCmd.PersistentFlags().StringVar(&secret, "s", "", "secret (for HMAC algorithms: HS256 requires 32+ bytes, HS384 requires 48+ bytes, HS512 requires 64+ bytes)")
	decodeCmd.PersistentFlags().BoolVar(&allowWeakSecret, "allow-weak-secret", false, "allow weak secrets for HMAC algorithms (for testing purposes only)")
	_ = decodeCmd.MarkPersistentFlagFilename("pk", "pem", "key")
	_ = decodeCmd.MarkPersistentFlagFilename("pubk", "pem", "key")
	_ = decodeCmd.MarkPersistentFlagFilename("t", "jwt", "txt")

	// decode subcommands
	decodeCmd.AddCommand(decodeRS256Cmd)
	decodeCmd.AddCommand(decodeRS384Cmd)
	decodeCmd.AddCommand(decodeRS512Cmd)
	decodeCmd.AddCommand(decodeES256Cmd)
	decodeCmd.AddCommand(decodeES384Cmd)
	decodeCmd.AddCommand(decodeES512Cmd)
	decodeCmd.AddCommand(decodeHS256Cmd)
	decodeCmd.AddCommand(decodeHS384Cmd)
	decodeCmd.AddCommand(decodeHS512Cmd)

	// genkeys
	rootCmd.AddCommand(genkeysCmd)
	genkeysCmd.AddCommand(genkeysES256Cmd)
	genkeysCmd.AddCommand(genkeysES384Cmd)
	genkeysCmd.AddCommand(genkeysES512Cmd)
	genkeysCmd.AddCommand(genkeysRS256Cmd)
	genkeysCmd.AddCommand(genkeysRS384Cmd)
	genkeysCmd.AddCommand(genkeysRS512Cmd)
}
