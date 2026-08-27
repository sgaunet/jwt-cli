package cmd

import (
	"github.com/spf13/cobra"
)

// createPasetoEncodeLocalCommand builds the "paseto encode local" command.
//
// It is a factory rather than a package-level literal so that each test can
// build a fresh instance: Cobra retains parsed flag values on a command.
//
//nolint:funlen // Long help and guidance text dominate this function
func createPasetoEncodeLocalCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   pasetoPurposeLocal,
		Short: "Encode a PASETO local (symmetric) token",
		Long: `Encode a JSON payload into a PASETO local token using symmetric encryption.

Local tokens are encrypted and authenticated with a single shared key, which
must be kept confidential. The same key is used to encode and decode.

Key Requirements:
  A hex-encoded 32-byte key, which "openssl rand -hex 32" produces.`,
		Example: `  # Encode a v4 local token
  jwt-cli paseto encode local --key "$(openssl rand -hex 32)" --payload '{"user":"alice"}'

  # Encode with an expiration (RFC 3339 or a Unix timestamp)
  jwt-cli paseto encode local --key "$KEY" --payload '{"user":"alice","exp":"2030-01-01T00:00:00Z"}'
  jwt-cli paseto encode local --key "$KEY" --payload '{"user":"alice","exp":1893456000}'

  # Encode a v3 local token
  jwt-cli paseto encode local --version v3 --key "$KEY" --payload '{"user":"alice"}'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, _ := cmd.Flags().GetString(flagKey)
			payload := flagWithFallback(cmd, flagPayload, aliasPayload)
			version := pasetoVersionFlag(cmd)

			if key == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return userError(`Error: key is required

Local PASETO tokens are encrypted with a symmetric key that must be kept confidential.

Example usage:
  jwt-cli paseto encode local --key "$(openssl rand -hex 32)" --payload '{"user":"alice"}'

Tip: The key must be hex-encoded and 32 bytes long. Generate one with 'openssl rand -hex 32'.`)
			}
			if payload == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return userError(`Error: payload is required

The payload contains the claims (data) to be encoded in the PASETO token.

Example usage:
  jwt-cli paseto encode local --key "$KEY" --payload '{"user":"alice","role":"admin"}'

Tip: Payload must be valid JSON. The registered claims exp, nbf and iat accept
     an RFC 3339 timestamp or a Unix timestamp.`)
			}

			encoder, err := newLocalCodec(version, key)
			if err != nil {
				return userError(err.Error())
			}

			token, err := encoder.Encode(payload)
			if err != nil {
				return userErrorf("encoding failed: %v", err)
			}
			outputToken(token)
			return nil
		},
	}
	registerPasetoEncodeLocalFlags(cmd)
	return cmd
}

var pasetoEncodeLocalCmd = createPasetoEncodeLocalCommand()
