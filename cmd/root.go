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
	// Silence Cobra's own error printing: command failures are reported through
	// userError(), which renders them via output() (and honours --json), and
	// Execute() reports anything else exactly once.
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command.
// When a command returns an error via RunE, we exit with code 1. Errors that no
// command has printed yet - Cobra's flag-parse and unknown-command errors - are
// reported here so they are not silently swallowed.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		reportError(err)
		os.Exit(1)
	}
}

func init() {
	// --json is the only persistent flag. Every other flag is declared by the
	// leaf command that reads it, in flags.go, so that passing a flag from
	// another algorithm family is an error rather than a silent no-op.
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
	// Keep Cobra's generated "completion" command available.
	rootCmd.CompletionOptions.DisableDefaultCmd = false

	registerJWTCommands()
	registerPasetoCommands()
}

// registerJWTCommands wires the JWT encode, decode and genkeys trees onto root.
func registerJWTCommands() {
	requireValidSubcommand(encodeCmd)
	requireValidSubcommand(decodeCmd)
	requireValidSubcommand(genkeysCmd)

	rootCmd.AddCommand(encodeCmd)
	encodeCmd.AddCommand(
		encodeRS256Cmd, encodeRS384Cmd, encodeRS512Cmd,
		encodeES256Cmd, encodeES384Cmd, encodeES512Cmd,
		encodeHS256Cmd, encodeHS384Cmd, encodeHS512Cmd,
	)

	rootCmd.AddCommand(decodeCmd)
	decodeCmd.AddCommand(
		decodeRS256Cmd, decodeRS384Cmd, decodeRS512Cmd,
		decodeES256Cmd, decodeES384Cmd, decodeES512Cmd,
		decodeHS256Cmd, decodeHS384Cmd, decodeHS512Cmd,
	)

	rootCmd.AddCommand(genkeysCmd)
	genkeysCmd.AddCommand(
		genkeysES256Cmd, genkeysES384Cmd, genkeysES512Cmd,
		genkeysRS256Cmd, genkeysRS384Cmd, genkeysRS512Cmd,
	)
}

// registerPasetoCommands wires the PASETO tree onto root.
func registerPasetoCommands() {
	requireValidSubcommand(pasetoCmd)
	requireValidSubcommand(pasetoEncodeCmd)
	requireValidSubcommand(pasetoDecodeCmd)
	requireValidSubcommand(pasetoGenkeysCmd)

	rootCmd.AddCommand(pasetoCmd)
	pasetoCmd.AddCommand(pasetoEncodeCmd, pasetoDecodeCmd, pasetoGenkeysCmd)
	pasetoEncodeCmd.AddCommand(pasetoEncodeLocalCmd, pasetoEncodePublicCmd)
	pasetoDecodeCmd.AddCommand(pasetoDecodeLocalCmd, pasetoDecodePublicCmd)
	pasetoGenkeysCmd.AddCommand(pasetoGenkeysV2Cmd, pasetoGenkeysV3Cmd, pasetoGenkeysV4Cmd)
}
