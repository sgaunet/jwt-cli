package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// createPasetoDecodePublicCommand builds the "paseto decode public" command.
//
//nolint:funlen // Long help and guidance text dominate this function
func createPasetoDecodePublicCommand() *cobra.Command {
	return &cobra.Command{
		Use:   pasetoPurposePublic,
		Short: "Decode a PASETO public (asymmetric) token",
		Long: `Decode and verify a PASETO public token using its signing key pair.

Either the public key (recommended) or the private key may be supplied; when
both are given the public key is used, following asymmetric key practice.

Claims Validation:
  The token's signature is verified, but time-based claims are NOT validated:
  an expired token still decodes successfully.`,
		Example: `  # Decode with the public key (recommended)
  jwt-cli paseto decode public --public-key paseto-v4-public.pem --token "$TOKEN"

  # Decode with the private key
  jwt-cli paseto decode public --private-key paseto-v4-private.pem --token "$TOKEN"

  # Decode a v3 public token (NIST P-384)
  jwt-cli paseto decode public --version v3 --public-key paseto-v3-public.pem --token "$TOKEN"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			privateKeyFile := pasetoFlag(cmd, "private-key", "pk")
			publicKeyFile := pasetoFlag(cmd, "public-key", "pubk")
			token := pasetoFlag(cmd, "token", "t")
			version := pasetoVersionFlag(cmd)

			if privateKeyFile == "" && publicKeyFile == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return pasetoError(`Error: key file is required

Provide either a public key file (recommended) or a private key file to verify the PASETO token.

Example usage with public key (recommended):
  jwt-cli paseto decode public --public-key paseto-v4-public.pem --token "$TOKEN"

Example usage with private key:
  jwt-cli paseto decode public --private-key paseto-v4-private.pem --token "$TOKEN"

Tip: The key must match the one used to encode the token.
     v2 and v4 use Ed25519 keys; v3 uses NIST P-384 keys.`)
			}
			if token == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return pasetoError(`Error: token is required

Provide the PASETO token string to decode and verify.

Example usage:
  jwt-cli paseto decode public --public-key paseto-v4-public.pem --token "$TOKEN"

Tip: The token is the string produced by 'jwt-cli paseto encode public'.`)
			}

			decoder, err := newPublicCodec(version, privateKeyFile, publicKeyFile)
			if err != nil {
				return pasetoError(err.Error())
			}

			claims, err := decoder.Decode(token)
			if err != nil {
				return pasetoError(fmt.Sprintf("decoding failed: %v", err))
			}
			outputClaims(claims)
			return nil
		},
	}
}

var pasetoDecodePublicCmd = createPasetoDecodePublicCommand()
