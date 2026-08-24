package cmd

import (
	"github.com/spf13/cobra"
)

// createPasetoDecodeLocalCommand builds the "paseto decode local" command.
func createPasetoDecodeLocalCommand() *cobra.Command {
	return &cobra.Command{
		Use:   pasetoPurposeLocal,
		Short: "Decode a PASETO local (symmetric) token",
		Long: `Decode and verify a PASETO local token using its symmetric key.

The same key used to encode the token is required to decode it.

Claims Validation:
  The token's authentication tag is verified, but time-based claims are NOT
  validated: an expired token still decodes successfully.`,
		Example: `  # Decode a v4 local token
  jwt-cli paseto decode local --key "$KEY" --token "v4.local.xxxxx"

  # Decode a v3 local token
  jwt-cli paseto decode local --version v3 --key "$KEY" --token "$TOKEN"

  # Extract a single claim
  jwt-cli paseto decode local --key "$KEY" --token "$TOKEN" | jq -r '.user'`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, _ := cmd.Flags().GetString("key")
			token := flagWithFallback(cmd, "token", "t")
			version := pasetoVersionFlag(cmd)

			if key == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return userError(`Error: key is required

Local PASETO tokens are decrypted with the same symmetric key used to encode them.

Example usage:
  jwt-cli paseto decode local --key "$KEY" --token "v4.local.xxxxx"

Tip: The key must be hex-encoded and 32 bytes long.`)
			}
			if token == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return userError(`Error: token is required

Provide the PASETO token string to decode and verify.

Example usage:
  jwt-cli paseto decode local --key "$KEY" --token "v4.local.xxxxx"
  jwt-cli paseto decode local --key "$KEY" --token "$TOKEN"

Tip: The token is the string produced by 'jwt-cli paseto encode local'.`)
			}

			decoder, err := newLocalCodec(version, key)
			if err != nil {
				return userError(err.Error())
			}

			claims, err := decoder.Decode(token)
			if err != nil {
				return userErrorf("decoding failed: %v", err)
			}
			outputClaims(claims)
			return nil
		},
	}
}

var pasetoDecodeLocalCmd = createPasetoDecodeLocalCommand()
