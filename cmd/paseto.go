package cmd

import (
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
  validate time-based claims by default: expired (exp) and not-yet-valid (nbf)
  tokens are decoded successfully so their contents can be inspected. Pass
  --validate-claims to "paseto decode" to enforce them instead.`,
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

Time-based claims are not validated by default: an expired token still decodes.
Use --validate-claims to reject expired (exp) or not-yet-valid (nbf) tokens, and
--clock-skew to allow tolerance for clock differences. A claim that is absent is
never enforced, and iat is never enforced.`,
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

// errUnsupportedVersion is the sentinel behind every unrecognised --version
// report. Use errors.Is to test for it.
//
//nolint:revive,staticcheck // User-facing error message with proper formatting
var errUnsupportedVersion = errors.New(`Error: unsupported PASETO version`)

// errUnsupportedPasetoVersion reports an unrecognised --version value.
func errUnsupportedPasetoVersion(version string) error {
	//nolint:revive,staticcheck // User-facing error message with proper formatting
	return fmt.Errorf(`%w: %q

Supported versions are v2, v3 and v4.

Example usage:
  jwt-cli paseto encode local --version v4 --key "$(openssl rand -hex 32)" --payload '{"user":"alice"}'

Tip: v4 is the recommended default. Use v3 only when a NIST-approved
     algorithm (P-384) is required.`, errUnsupportedVersion, version)
}

// newLocalCodec builds an encoder/decoder for PASETO local (symmetric) tokens.
func newLocalCodec(version, keyHex string, opts ...paseto.Option) (paseto.EncoderDecoder, error) {
	var (
		codec paseto.EncoderDecoder
		err   error
	)
	switch version {
	case pasetoV4:
		codec, err = paseto.NewLocalV4Encoder(keyHex, opts...)
	case pasetoV3:
		codec, err = paseto.NewLocalV3Encoder(keyHex, opts...)
	case pasetoV2:
		codec, err = paseto.NewLocalV2Encoder(keyHex, opts...)
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
func newPublicCodec(version, privateKeyFile, publicKeyFile string, opts ...paseto.Option) (paseto.EncoderDecoder, error) {
	var (
		codec paseto.EncoderDecoder
		err   error
	)
	usePublicKey := publicKeyFile != ""
	switch version {
	case pasetoV4:
		if usePublicKey {
			codec, err = paseto.NewPublicV4DecoderFromPublicKey(publicKeyFile, opts...)
		} else {
			codec, err = paseto.NewPublicV4EncoderFromPrivateKey(privateKeyFile, opts...)
		}
	case pasetoV3:
		if usePublicKey {
			codec, err = paseto.NewPublicV3DecoderFromPublicKey(publicKeyFile, opts...)
		} else {
			codec, err = paseto.NewPublicV3EncoderFromPrivateKey(privateKeyFile, opts...)
		}
	case pasetoV2:
		if usePublicKey {
			codec, err = paseto.NewPublicV2DecoderFromPublicKey(publicKeyFile, opts...)
		} else {
			codec, err = paseto.NewPublicV2EncoderFromPrivateKey(privateKeyFile, opts...)
		}
	default:
		return nil, errUnsupportedPasetoVersion(version)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	return codec, nil
}

// pasetoVersionFlag reads the --version flag, defaulting to v4 when unset.
func pasetoVersionFlag(cmd *cobra.Command) string {
	version, _ := cmd.Flags().GetString("version")
	if version == "" {
		return pasetoV4
	}
	return version
}

// pasetoValidationOption reads the claims-validation flags shared by the paseto
// decode subcommands.
//
// Validation is off by default, so a token can always be inspected regardless
// of its timing claims; --clock-skew only matters once --validate-claims is on.
func pasetoValidationOption(cmd *cobra.Command) paseto.Option {
	validateClaims, _ := cmd.Flags().GetBool("validate-claims")
	clockSkew, _ := cmd.Flags().GetDuration("clock-skew")
	return paseto.WithValidation(paseto.ValidationOptions{
		ValidateClaims: validateClaims,
		ClockSkew:      clockSkew,
	})
}

// newLocalDecoder builds a decoder for local tokens, honouring the claims
// validation flags.
func newLocalDecoder(cmd *cobra.Command, version, keyHex string) (paseto.EncoderDecoder, error) {
	return newLocalCodec(version, keyHex, pasetoValidationOption(cmd))
}

// newPublicDecoder builds a decoder for public tokens, honouring the claims
// validation flags.
func newPublicDecoder(cmd *cobra.Command, version, privateKeyFile, publicKeyFile string) (paseto.EncoderDecoder, error) {
	return newPublicCodec(version, privateKeyFile, publicKeyFile, pasetoValidationOption(cmd))
}
