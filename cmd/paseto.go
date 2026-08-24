package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sgaunet/jwt-cli/pkg/paseto"
	"github.com/spf13/cobra"
)

// Supported PASETO versions.
const (
	pasetoV2 = "v2"
	pasetoV3 = "v3"
	pasetoV4 = "v4"
)

// PASETO token purposes and subcommand names.
const (
	pasetoPurposeLocal  = "local"
	pasetoPurposePublic = "public"
	pasetoVerbEncode    = "encode"
	pasetoVerbDecode    = "decode"
	pasetoVerbGenkeys   = "genkeys"
)

// pasetoVersions lists the supported versions, for validation and completion.
var pasetoVersions = []string{pasetoV2, pasetoV3, pasetoV4}

// pasetoCmd represents the paseto command.
var pasetoCmd = &cobra.Command{
	Use:   "paseto",
	Short: "Encode and decode PASETO tokens",
	Long: `Encode and decode PASETO (Platform-Agnostic SEcurity TOkens).

PASETO is an alternative to JWT that avoids algorithm confusion attacks by
binding each token to a specific version and purpose.

Supported versions:
  - v2, v4: Ed25519 for public tokens, XChaCha20-Poly1305 for local tokens
  - v3:     NIST P-384 for public tokens, AES-CTR + HMAC for local tokens

Token purposes:
  - local:  symmetric encryption using a hex-encoded 32-byte key
  - public: asymmetric signing using a key pair in PEM or raw form

Claims Validation:
  Decoding verifies the token's signature or authentication tag, but does NOT
  validate time-based claims: expired (exp) and not-yet-valid (nbf) tokens are
  decoded successfully so their contents can be inspected.`,
	Example: `  # Generate a symmetric key and encode a local token
  jwt-cli paseto encode local --key "$(openssl rand -hex 32)" --payload '{"user":"alice"}'

  # Show how to generate a key pair for public tokens
  jwt-cli paseto genkeys v4`,
	ValidArgs: []string{pasetoVerbEncode, pasetoVerbDecode, pasetoVerbGenkeys},
}

// pasetoEncodeCmd represents the paseto encode command.
var pasetoEncodeCmd = &cobra.Command{
	Use:       pasetoVerbEncode,
	Short:     "Encode a PASETO token",
	Long:      `Encode a JSON payload into a PASETO local (symmetric) or public (asymmetric) token.`,
	ValidArgs: []string{pasetoPurposeLocal, pasetoPurposePublic},
}

// pasetoDecodeCmd represents the paseto decode command.
var pasetoDecodeCmd = &cobra.Command{
	Use:   pasetoVerbDecode,
	Short: "Decode a PASETO token",
	Long: `Decode and verify a PASETO local (symmetric) or public (asymmetric) token.

Time-based claims are not validated: an expired token still decodes.`,
	ValidArgs: []string{pasetoPurposeLocal, pasetoPurposePublic},
}

// pasetoGenkeysCmd represents the paseto genkeys command.
var pasetoGenkeysCmd = &cobra.Command{
	Use:   pasetoVerbGenkeys,
	Short: "Print commands to generate PASETO keys",
	Long: `Print example OpenSSL commands to generate key pairs for PASETO public tokens.

Key types by version:
  - v2, v4: Ed25519
  - v3:     NIST P-384

Local (symmetric) tokens do not need a key pair: use a hex-encoded 32-byte key,
which "openssl rand -hex 32" produces.`,
	Example: `  # Show commands for v4 key generation
  jwt-cli paseto genkeys v4

  # Generate the keys by running the output
  $(jwt-cli paseto genkeys v4)`,
	ValidArgs: pasetoVersions,
}

// errUnsupportedPasetoVersion reports an unrecognised --version value.
func errUnsupportedPasetoVersion(version string) error {
	//nolint:revive,staticcheck // User-facing error message with proper formatting
	return fmt.Errorf(`Error: unsupported PASETO version: %q

Supported versions are v2, v3 and v4.

Example usage:
  jwt-cli paseto encode local --version v4 --key "$(openssl rand -hex 32)" --payload '{"user":"alice"}'

Tip: v4 is the recommended default. Use v3 only when a NIST-approved
     algorithm (P-384) is required.`, version)
}

// newLocalCodec builds an encoder/decoder for PASETO local (symmetric) tokens.
func newLocalCodec(version, keyHex string) (paseto.EncoderDecoder, error) {
	var (
		codec paseto.EncoderDecoder
		err   error
	)
	switch version {
	case pasetoV4:
		codec, err = paseto.NewLocalV4Encoder(keyHex)
	case pasetoV3:
		codec, err = paseto.NewLocalV3Encoder(keyHex)
	case pasetoV2:
		codec, err = paseto.NewLocalV2Encoder(keyHex)
	default:
		return nil, errUnsupportedPasetoVersion(version)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	return codec, nil
}

// newPublicCodec builds an encoder/decoder for PASETO public (asymmetric)
// tokens.
//
// When a public key file is supplied it takes precedence, matching the JWT
// decode commands; the resulting value can only decode. Supplying a private key
// yields a value that can both sign and verify.
func newPublicCodec(version, privateKeyFile, publicKeyFile string) (paseto.EncoderDecoder, error) {
	var (
		codec paseto.EncoderDecoder
		err   error
	)
	usePublicKey := publicKeyFile != ""
	switch version {
	case pasetoV4:
		if usePublicKey {
			codec, err = paseto.NewPublicV4DecoderFromPublicKey(publicKeyFile)
		} else {
			codec, err = paseto.NewPublicV4EncoderFromPrivateKey(privateKeyFile)
		}
	case pasetoV3:
		if usePublicKey {
			codec, err = paseto.NewPublicV3DecoderFromPublicKey(publicKeyFile)
		} else {
			codec, err = paseto.NewPublicV3EncoderFromPrivateKey(privateKeyFile)
		}
	case pasetoV2:
		if usePublicKey {
			codec, err = paseto.NewPublicV2DecoderFromPublicKey(publicKeyFile)
		} else {
			codec, err = paseto.NewPublicV2EncoderFromPrivateKey(privateKeyFile)
		}
	default:
		return nil, errUnsupportedPasetoVersion(version)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	return codec, nil
}

// pasetoError reports a user-facing failure and returns it so the command
// exits non-zero.
//
// Every PASETO failure is routed through output(): rootCmd sets
// SilenceErrors, so an error merely returned from RunE would exit 1 without
// printing anything, and only output() renders the --json failure envelope.
func pasetoError(msg string) error {
	output(CommandOutput{Success: false, Error: msg})
	return errors.New(msg)
}

// pasetoFlag reads a flag, falling back to its deprecated short alias.
func pasetoFlag(cmd *cobra.Command, name, deprecated string) string {
	value, _ := cmd.Flags().GetString(name)
	if value == "" {
		value, _ = cmd.Flags().GetString(deprecated) // Check deprecated flag
	}
	return value
}

// pasetoVersionFlag reads the --version flag, defaulting to v4 when unset.
func pasetoVersionFlag(cmd *cobra.Command) string {
	version, _ := cmd.Flags().GetString("version")
	if version == "" {
		return pasetoV4
	}
	return version
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
