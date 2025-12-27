package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createHSDecodeCommand(_ /* alg */, use, short, long, example string, decoderWithValidation func([]byte, bool, cryptojwt.ValidationOptions) cryptojwt.EncoderDecoder) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		RunE: func(cmd *cobra.Command, _ []string) error {
			secret, _ := cmd.Flags().GetString("secret")
			if secret == "" {
				secret, _ = cmd.Flags().GetString("s") // Check deprecated flag
			}
			token, _ := cmd.Flags().GetString("token")
			if token == "" {
				token, _ = cmd.Flags().GetString("t") // Check deprecated flag
			}
			allowWeakSecret, _ := cmd.Flags().GetBool("allow-weak-secret")
			validateClaims, _ := cmd.Flags().GetBool("validate-claims")
			clockSkew, _ := cmd.Flags().GetDuration("clock-skew")

			if secret == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: secret is required

The secret is used to verify the JWT token signature. It must match the secret used for encoding.

Example usage:
  jwt-cli decode %s --token "eyJhbGci..." --secret "your-secret-key"

Tip: Use the same secret that was used to encode the token.
     HS256 requires at least 32 bytes, HS384 requires 48 bytes, HS512 requires 64 bytes.`, use)
			}
			if token == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: token is required

Provide the JWT token string to decode and verify.

Example usage:
  jwt-cli decode %s --token "eyJhbGci..." --secret "your-secret-key"
  jwt-cli decode %s --token "$TOKEN" --secret "your-secret-key"

Tip: The token is the three-part string (header.payload.signature) produced by the encode command.`, use, use)
			}

			validationOpts := cryptojwt.ValidationOptions{
				ValidateClaims: validateClaims,
				ClockSkew:      clockSkew,
			}

			j := decoderWithValidation([]byte(secret), allowWeakSecret, validationOpts)
			claims, err := j.Decode(token)
			if err != nil {
				errMsg := fmt.Sprintf("decoding failed: %v", err)
				output(CommandOutput{Success: false, Error: errMsg})
				return errors.New(errMsg)
			}
			// Parse claims string as JSON for structured output
			var claimsData any
			if err := json.Unmarshal([]byte(claims), &claimsData); err != nil {
				// If claims aren't valid JSON, treat as raw string
				claimsData = claims
			}
			output(CommandOutput{Success: true, Claims: claimsData})
			return nil
		},
	}
}

var decodeHS256Cmd = createHSDecodeCommand(
	"HS256",
	"hs256",
	"Decode JWT token using HS256 (HMAC-SHA256) algorithm",
	`Decode and verify a JWT token signed with HS256.

HS256 uses HMAC with SHA-256 for verification. The same secret used
to encode the token must be provided to verify and decode it.

Secret Requirements:
  HS256 requires a minimum of 32 bytes (256 bits) for the secret according
  to RFC 7518 Section 3.2. Use --allow-weak-secret flag to bypass validation
  for testing purposes only.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated for backward
  compatibility. Use --validate-claims to enable validation and reject expired
  or not-yet-valid tokens. Use --clock-skew to allow tolerance for clock differences.`,
	`  # Decode a token
  jwt-cli decode hs256 --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --secret "my-32-byte-secret-key-for-hs256"

  # Decode token from variable
  jwt-cli decode hs256 --token "$TOKEN" --secret "my-32-byte-secret-key-for-hs256"

  # Decode with claims validation (reject expired tokens)
  jwt-cli decode hs256 --token "$TOKEN" --secret "my-32-byte-secret-key-for-hs256" --validate-claims

  # Decode with claims validation and 5-minute clock skew tolerance
  jwt-cli decode hs256 --token "$TOKEN" --secret "my-32-byte-secret-key-for-hs256" --validate-claims --clock-skew 5m

  # Decode and extract specific field with jq
  jwt-cli decode hs256 --token "$TOKEN" --secret "my-32-byte-secret-key-for-hs256" | jq -r '.user'`,
	cryptojwt.NewHS256DecoderWithValidation,
)

var decodeHS384Cmd = createHSDecodeCommand(
	"HS384",
	"hs384",
	"Decode JWT token using HS384 (HMAC-SHA384) algorithm",
	`Decode and verify a JWT token signed with HS384.

HS384 uses HMAC with SHA-384 for verification. The same secret used
to encode the token must be provided to verify and decode it.

Secret Requirements:
  HS384 requires a minimum of 48 bytes (384 bits) for the secret according
  to RFC 7518 Section 3.2. Use --allow-weak-secret flag to bypass validation
  for testing purposes only.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode a token
  jwt-cli decode hs384 --token "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9..." --secret "my-48-byte-secret-key-for-hs384-authentication"

  # Decode token from variable
  jwt-cli decode hs384 --token "$TOKEN" --secret "my-48-byte-secret-key-for-hs384-authentication"

  # Decode with claims validation
  jwt-cli decode hs384 --token "$TOKEN" --secret "my-48-byte-secret-key-for-hs384-authentication" --validate-claims`,
	cryptojwt.NewHS384DecoderWithValidation,
)

var decodeHS512Cmd = createHSDecodeCommand(
	"HS512",
	"hs512",
	"Decode JWT token using HS512 (HMAC-SHA512) algorithm",
	`Decode and verify a JWT token signed with HS512.

HS512 uses HMAC with SHA-512 for verification. The same secret used
to encode the token must be provided to verify and decode it.

Secret Requirements:
  HS512 requires a minimum of 64 bytes (512 bits) for the secret according
  to RFC 7518 Section 3.2. Use --allow-weak-secret flag to bypass validation
  for testing purposes only.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode a token
  jwt-cli decode hs512 --token "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..." --secret "my-64-byte-secret-key-for-hs512-that-meets-minimum-requirement"

  # Decode token from variable
  jwt-cli decode hs512 --token "$TOKEN" --secret "my-64-byte-secret-key-for-hs512-that-meets-minimum-requirement"

  # Decode with claims validation and clock skew
  jwt-cli decode hs512 --token "$TOKEN" --secret "my-64-byte-secret-key-for-hs512-that-meets-minimum-requirement" --validate-claims --clock-skew 1m`,
	cryptojwt.NewHS512DecoderWithValidation,
)