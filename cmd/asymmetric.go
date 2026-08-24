package cmd

import (
	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

// asymmetricKeyVocab carries the key-type wording that distinguishes the ECDSA
// and RSA command help text. The commands are otherwise identical, so both
// families share the constructors below.
type asymmetricKeyVocab struct {
	// keyType names the algorithm family in prose, e.g. "ECDSA".
	keyType string
	// privateKeyPath is the private key path shown in example commands.
	privateKeyPath string
	// publicKeyPath is the public key path shown in example commands.
	publicKeyPath string
	// encodeKeyTip closes the encode "key required" error with family-specific advice.
	encodeKeyTip string
	// decodeKeyTip appends an extra line to the decode "key required" tip, or is
	// empty when the family has nothing to add.
	decodeKeyTip string
}

// asymmetricEncoderFunc builds an encoder from a private key file. allowWeakKey
// is meaningful only for RSA; the ECDSA commands adapt their constructors with
// ignoreWeakKeyEncoder.
type asymmetricEncoderFunc func(privateKeyFile string, allowWeakKey bool) cryptojwt.Encoder

// asymmetricDecoderFunc builds a decoder from a key file. allowWeakKey is
// meaningful only for RSA; see ignoreWeakKeyDecoder.
type asymmetricDecoderFunc func(
	keyFile string, validationOpts cryptojwt.ValidationOptions, allowWeakKey bool,
) cryptojwt.Decoder

// ignoreWeakKeyEncoder adapts an encoder constructor that has no weak-key
// opt-out. ECDSA key sizes are fixed by the curve the algorithm names, so there
// is nothing for --allow-weak-key to override.
func ignoreWeakKeyEncoder(f func(string) cryptojwt.Encoder) asymmetricEncoderFunc {
	return func(privateKeyFile string, _ bool) cryptojwt.Encoder {
		return f(privateKeyFile)
	}
}

// ignoreWeakKeyDecoder adapts a decoder constructor that has no weak-key opt-out.
func ignoreWeakKeyDecoder(
	f func(string, cryptojwt.ValidationOptions) cryptojwt.Decoder,
) asymmetricDecoderFunc {
	return func(keyFile string, validationOpts cryptojwt.ValidationOptions, _ bool) cryptojwt.Decoder {
		return f(keyFile, validationOpts)
	}
}

// esKeyVocab describes the ECDSA (ES256/384/512) commands.
var esKeyVocab = asymmetricKeyVocab{
	keyType:        "ECDSA",
	privateKeyPath: "./keys/ec-private.pem",
	publicKeyPath:  "./keys/ec-public.pem",
	encodeKeyTip: `Tip: ECDSA provides strong security with smaller key sizes compared to RSA.
     ES256 uses P-256 curve, ES384 uses P-384, ES512 uses P-521.`,
	decodeKeyTip: `
     ES256 uses P-256 curve, ES384 uses P-384, ES512 uses P-521.`,
}

// rsKeyVocab describes the RSA (RS256/384/512) commands.
var rsKeyVocab = asymmetricKeyVocab{
	keyType:        "RSA",
	privateKeyPath: "./keys/private.pem",
	publicKeyPath:  "./keys/public.pem",
	encodeKeyTip: `Tip: Keep your private key secure and never share it. RSA keys must be at
     least 2048 bits; pass --allow-weak-key to accept a shorter one for testing.`,
	decodeKeyTip: "",
}

// createAsymmetricEncodeCommand builds an encode command for a private-key
// signing algorithm. HMAC encoding uses createHSEncodeCommand instead: its flag
// set (--secret, --allow-weak-secret) is genuinely different.
func createAsymmetricEncodeCommand(
	v asymmetricKeyVocab,
	use, short, long, example string,
	encoder asymmetricEncoderFunc,
) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		RunE: func(cmd *cobra.Command, _ []string) error {
			privateKeyFile := flagWithFallback(cmd, "private-key", "pk")
			payload := flagWithFallback(cmd, "payload", "p")
			allowWeakKey, _ := cmd.Flags().GetBool("allow-weak-key")

			if privateKeyFile == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return userErrorf(`Error: private key file is required

Provide the path to your %s private key file in PEM format for signing the JWT token.

Example usage:
  jwt-cli encode %s --private-key %s --payload '{"sub":"1234567890","name":"Alice"}'

Generate keys with:
  jwt-cli genkeys %s

%s`, v.keyType, use, v.privateKeyPath, use, v.encodeKeyTip)
			}
			if payload == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return userErrorf(`Error: payload is required

The payload contains the claims (data) to be encoded in the JWT token.

Example usage:
  jwt-cli encode %s --private-key %s --payload '{"sub":"1234567890","name":"Alice"}'

Tip: Payload must be valid JSON. Common claims include 'sub' (subject), 'exp' (expiration), 'iat' (issued at).`,
					use, v.privateKeyPath)
			}

			j := encoder(privateKeyFile, allowWeakKey)
			t, err := j.Encode(payload)
			if err != nil {
				return userErrorf("encoding failed: %v", err)
			}
			outputToken(t)
			return nil
		},
	}
}

// createAsymmetricDecodeCommand builds a decode command for a key-pair
// algorithm. The public key takes precedence when both keys are supplied,
// following asymmetric key practice.
//
//nolint:funlen // Long user-facing guidance text dominates this function
func createAsymmetricDecodeCommand(
	v asymmetricKeyVocab,
	use, short, long, example string,
	pubKeyDecoderWithValidation, privKeyDecoderWithValidation asymmetricDecoderFunc,
) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		RunE: func(cmd *cobra.Command, _ []string) error {
			privateKeyFile := flagWithFallback(cmd, "private-key", "pk")
			publicKeyFile := flagWithFallback(cmd, "public-key", "pubk")
			token := flagWithFallback(cmd, "token", "t")
			validateClaims, _ := cmd.Flags().GetBool("validate-claims")
			clockSkew, _ := cmd.Flags().GetDuration("clock-skew")
			allowWeakKey, _ := cmd.Flags().GetBool("allow-weak-key")

			if privateKeyFile == "" && publicKeyFile == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return userErrorf(`Error: key file is required

Provide either a public key file (recommended) or private key file in PEM format to verify the JWT token.

Example usage with public key (recommended):
  jwt-cli decode %s --token "eyJhbGci..." --public-key %s

Example usage with private key:
  jwt-cli decode %s --token "eyJhbGci..." --private-key %s

Tip: Use the public key for verification to follow asymmetric cryptography best practices.
     The key must match the one used to encode the token.%s`,
					use, v.publicKeyPath, use, v.privateKeyPath, v.decodeKeyTip)
			}
			if token == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return userErrorf(`Error: token is required

Provide the JWT token string to decode and verify.

Example usage:
  jwt-cli decode %s --token "eyJhbGci..." --public-key %s
  jwt-cli decode %s --token "$TOKEN" --public-key %s

Tip: The token is the three-part string (header.payload.signature) produced by the encode command.`,
					use, v.publicKeyPath, use, v.publicKeyPath)
			}

			validationOpts := cryptojwt.ValidationOptions{
				ValidateClaims: validateClaims,
				ClockSkew:      clockSkew,
			}

			var j cryptojwt.Decoder
			if publicKeyFile != "" {
				j = pubKeyDecoderWithValidation(publicKeyFile, validationOpts, allowWeakKey)
			} else {
				j = privKeyDecoderWithValidation(privateKeyFile, validationOpts, allowWeakKey)
			}

			claims, err := j.Decode(token)
			if err != nil {
				return userErrorf("decoding failed: %v", err)
			}
			outputClaims(claims)
			return nil
		},
	}
}
