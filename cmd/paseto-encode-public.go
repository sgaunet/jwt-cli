package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// createPasetoEncodePublicCommand builds the "paseto encode public" command.
//
//nolint:funlen // Long help and guidance text dominate this function
func createPasetoEncodePublicCommand() *cobra.Command {
	return &cobra.Command{
		Use:   pasetoPurposePublic,
		Short: "Encode a PASETO public (asymmetric) token",
		Long: `Encode a JSON payload into a PASETO public token using asymmetric signing.

Public tokens are signed with a private key and verified with the matching
public key. The payload is signed but NOT encrypted, so it is readable by
anyone holding the token.

Key Requirements:
  - v2, v4: an Ed25519 private key
  - v3:     a NIST P-384 private key
  Keys may be supplied as PEM (PKCS#8, or SEC 1 for v3) or as raw key bytes.
  Run 'jwt-cli paseto genkeys <version>' for the generation commands.`,
		Example: `  # Encode a v4 public token
  jwt-cli paseto encode public --private-key paseto-v4-private.pem --payload '{"user":"alice"}'

  # Encode a v3 public token (NIST P-384)
  jwt-cli paseto encode public --version v3 --private-key paseto-v3-private.pem --payload '{"user":"alice"}'

  # Store the token in a variable
  TOKEN=$(jwt-cli paseto encode public --private-key paseto-v4-private.pem --payload '{"user":"alice"}')`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			privateKeyFile := pasetoFlag(cmd, "private-key", "pk")
			payload := pasetoFlag(cmd, "payload", "p")
			version := pasetoVersionFlag(cmd)

			if privateKeyFile == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return pasetoError(`Error: private key file is required

Public PASETO tokens are signed with a private key.

Example usage:
  jwt-cli paseto encode public --private-key paseto-v4-private.pem --payload '{"user":"alice"}'

Tip: Run 'jwt-cli paseto genkeys v4' to see how to generate a key pair.
     v2 and v4 use Ed25519 keys; v3 uses NIST P-384 keys.`)
			}
			if payload == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return pasetoError(`Error: payload is required

The payload contains the claims (data) to be encoded in the PASETO token.

Example usage:
  jwt-cli paseto encode public --private-key paseto-v4-private.pem --payload '{"user":"alice","role":"admin"}'

Tip: Payload must be valid JSON. The registered claims exp, nbf and iat accept
     an RFC 3339 timestamp or a Unix timestamp.`)
			}

			encoder, err := newPublicCodec(version, privateKeyFile, "")
			if err != nil {
				return pasetoError(err.Error())
			}

			token, err := encoder.Encode(payload)
			if err != nil {
				return pasetoError(fmt.Sprintf("encoding failed: %v", err))
			}
			outputToken(token)
			return nil
		},
	}
}

var pasetoEncodePublicCmd = createPasetoEncodePublicCommand()
