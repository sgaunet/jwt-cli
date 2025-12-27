// Package cmd implements the command-line interface for jwt-cli.
//
// The package provides Cobra commands for encoding and decoding JWT tokens
// with support for multiple algorithms: HS256/384/512, RS256/384/512, and ES256/384/512.
//
// Each algorithm type has dedicated subcommands under encode and decode:
//   - encode hs256/hs384/hs512: HMAC-based encoding with shared secrets
//   - encode rs256/rs384/rs512: RSA-based encoding with private keys
//   - encode es256/es384/es512: ECDSA-based encoding with private keys
//   - decode hs256/hs384/hs512: HMAC-based decoding with shared secrets
//   - decode rs256/rs384/rs512: RSA-based decoding with public/private keys
//   - decode es256/es384/es512: ECDSA-based decoding with public/private keys
//
// Additional commands include:
//   - genkeys: Generate example key pairs for testing
//   - version: Display version information
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// jsonOutput controls whether to output in JSON format or human-readable format.
var jsonOutput bool

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
  jwt-cli encode rs256 --payload '{"user":"alice"}' --private-key RS256.key`,
	// Silence errors because the output() function already prints them appropriately
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command.
// When a command returns an error via RunE, we exit with code 1.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

//nolint:funlen // init function requires many statements for command setup
func init() {
	// Global flags for all commands
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")

	rootCmd.AddCommand(encodeCmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = false
	encodeCmd.PersistentFlags().StringP("payload", "p", "", "JSON payload to encode into JWT (e.g., '{\"user\":\"alice\"}')")
	encodeCmd.PersistentFlags().String("private-key", "", "path to RSA/ECDSA private key file in PEM format")
	encodeCmd.PersistentFlags().StringP("secret", "s", "", "HMAC secret for signing (minimum 32 bytes for HS256, 48 bytes for HS384, 64 bytes for HS512)")
	encodeCmd.PersistentFlags().Bool("allow-weak-secret", false, "allow weak secrets for HMAC algorithms (for testing purposes only)")
	_ = encodeCmd.MarkPersistentFlagFilename("private-key", "pem", "key")
	_ = encodeCmd.MarkPersistentFlagFilename("payload", "json")
	// Backward compatibility: add deprecated aliases for old flag names
	encodeCmd.PersistentFlags().String("p", "", "")
	_ = encodeCmd.PersistentFlags().MarkDeprecated("p", "use --payload or -p instead")
	encodeCmd.PersistentFlags().String("s", "", "")
	_ = encodeCmd.PersistentFlags().MarkDeprecated("s", "use --secret or -s instead")
	encodeCmd.PersistentFlags().String("pk", "", "")
	_ = encodeCmd.PersistentFlags().MarkDeprecated("pk", "use --private-key instead")

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
	decodeCmd.PersistentFlags().String("private-key", "", "path to RSA/ECDSA private key file in PEM format")
	decodeCmd.PersistentFlags().String("public-key", "", "path to RSA/ECDSA public key file in PEM format")
	decodeCmd.PersistentFlags().StringP("token", "t", "", "JWT token to decode and verify")
	decodeCmd.PersistentFlags().StringP("secret", "s", "", "HMAC secret for verification (minimum 32 bytes for HS256, 48 bytes for HS384, 64 bytes for HS512)")
	decodeCmd.PersistentFlags().Bool("allow-weak-secret", false, "allow weak secrets for HMAC algorithms (for testing purposes only)")
	decodeCmd.PersistentFlags().Bool("validate-claims", false, "validate JWT time-based claims (exp, nbf, iat) - reject expired or not-yet-valid tokens")
	decodeCmd.PersistentFlags().Duration("clock-skew", 0, "clock skew tolerance for claims validation (e.g., 5m, 30s)")
	_ = decodeCmd.MarkPersistentFlagFilename("private-key", "pem", "key")
	_ = decodeCmd.MarkPersistentFlagFilename("public-key", "pem", "key")
	_ = decodeCmd.MarkPersistentFlagFilename("token", "jwt", "txt")
	// Backward compatibility: add deprecated aliases for old flag names
	decodeCmd.PersistentFlags().String("pk", "", "")
	_ = decodeCmd.PersistentFlags().MarkDeprecated("pk", "use --private-key instead")
	decodeCmd.PersistentFlags().String("pubk", "", "")
	_ = decodeCmd.PersistentFlags().MarkDeprecated("pubk", "use --public-key instead")
	decodeCmd.PersistentFlags().String("t", "", "")
	_ = decodeCmd.PersistentFlags().MarkDeprecated("t", "use --token or -t instead")
	decodeCmd.PersistentFlags().String("s", "", "")
	_ = decodeCmd.PersistentFlags().MarkDeprecated("s", "use --secret or -s instead")

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
