package cmd

import (
	"github.com/spf13/cobra"
)

// createPasetoDecodeLocalCommand builds the "paseto decode local" command.
//
//nolint:funlen // Long help and guidance text dominate this function
func createPasetoDecodeLocalCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   pasetoPurposeLocal,
		Short: "Decode a PASETO local (symmetric) token",
		Long: `Decode and verify a PASETO local token using its symmetric key.

The same key used to encode the token is required to decode it.

Claims Validation:
  The token's authentication tag is verified, but time-based claims are NOT
  validated by default: an expired token still decodes successfully. Pass
  --validate-claims to reject expired (exp) or not-yet-valid (nbf) tokens, and
  --clock-skew to allow tolerance for clock differences.`,
		Example: `  # Decode a v4 local token
  jwt-cli paseto decode local --key "$KEY" --token "v4.local.xxxxx"

  # Decode a v3 local token
  jwt-cli paseto decode local --version v3 --key "$KEY" --token "$TOKEN"

  # Reject the token if it has expired
  jwt-cli paseto decode local --key "$KEY" --token "$TOKEN" --validate-claims

  # Same, tolerating five minutes of clock difference
  jwt-cli paseto decode local --key "$KEY" --token "$TOKEN" --validate-claims --clock-skew 5m

  # Extract a single claim
  jwt-cli paseto decode local --key "$KEY" --token "$TOKEN" | jq -r '.user'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, _ := cmd.Flags().GetString(flagKey)
			token := flagWithFallback(cmd, flagToken, aliasToken)
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

			decoder, err := newLocalDecoder(cmd, version, key)
			if err != nil {
				return userError(err.Error())
			}

			decoded, err := decoder.DecodeWithFooter(token)
			if err != nil {
				return userErrorf("decoding failed: %v", err)
			}
			outputPasetoClaims(decoded)
			return nil
		},
	}
	registerPasetoDecodeLocalFlags(cmd)
	return cmd
}

var pasetoDecodeLocalCmd = createPasetoDecodeLocalCommand()
