package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl,funlen // Similar structure needed for different algorithms
func createRSDecodeCommand(_ /* alg */, use, short, long, example string, pubKeyDecoderWithValidation, privKeyDecoderWithValidation func(string, cryptojwt.ValidationOptions) cryptojwt.Decoder) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		RunE: func(cmd *cobra.Command, _ []string) error {
			privateKeyFile, _ := cmd.Flags().GetString("private-key")
			if privateKeyFile == "" {
				privateKeyFile, _ = cmd.Flags().GetString("pk") // Check deprecated flag
			}
			publicKeyFile, _ := cmd.Flags().GetString("public-key")
			if publicKeyFile == "" {
				publicKeyFile, _ = cmd.Flags().GetString("pubk") // Check deprecated flag
			}
			token, _ := cmd.Flags().GetString("token")
			if token == "" {
				token, _ = cmd.Flags().GetString("t") // Check deprecated flag
			}
			validateClaims, _ := cmd.Flags().GetBool("validate-claims")
			clockSkew, _ := cmd.Flags().GetDuration("clock-skew")

			if privateKeyFile == "" && publicKeyFile == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: key file is required

Provide either a public key file (recommended) or private key file in PEM format to verify the JWT token.

Example usage with public key (recommended):
  jwt-cli decode %s --token "eyJhbGci..." --public-key ./keys/public.pem

Example usage with private key:
  jwt-cli decode %s --token "eyJhbGci..." --private-key ./keys/private.pem

Tip: Use the public key for verification to follow asymmetric cryptography best practices.
     The key must match the one used to encode the token.`, use, use)
			}
			if token == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: token is required

Provide the JWT token string to decode and verify.

Example usage:
  jwt-cli decode %s --token "eyJhbGci..." --public-key ./keys/public.pem
  jwt-cli decode %s --token "$TOKEN" --public-key ./keys/public.pem

Tip: The token is the three-part string (header.payload.signature) produced by the encode command.`, use, use)
			}

			validationOpts := cryptojwt.ValidationOptions{
				ValidateClaims: validateClaims,
				ClockSkew:      clockSkew,
			}

			var j cryptojwt.Decoder
			if publicKeyFile != "" {
				j = pubKeyDecoderWithValidation(publicKeyFile, validationOpts)
			} else {
				j = privKeyDecoderWithValidation(privateKeyFile, validationOpts)
			}

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

var decodeRS256Cmd = createRSDecodeCommand(
	"RS256",
	"rs256",
	"Decode JWT token using RS256 (RSA-SHA256) algorithm",
	`Decode and verify a JWT token signed with RS256.

RS256 uses RSA signature with SHA-256 hash for verification. You can
provide either the public key (recommended) or the private key for
verification. Using the public key is preferred as it follows the
asymmetric key principle.

Key Requirements:
  - Public or private key in PEM format
  - Key must match the one used for encoding

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key (recommended)
  jwt-cli decode rs256 --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." --public-key RS256.key.pub

  # Decode with private key
  jwt-cli decode rs256 --token "$TOKEN" --private-key RS256.key

  # Decode with claims validation
  jwt-cli decode rs256 --token "$TOKEN" --public-key RS256.key.pub --validate-claims

  # Decode and extract specific field
  jwt-cli decode rs256 --token "$TOKEN" --public-key RS256.key.pub | jq -r '.user'`,
	cryptojwt.NewRS256DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewRS256DecoderWithPrivateKeyFileAndValidation,
)

var decodeRS384Cmd = createRSDecodeCommand(
	"RS384",
	"rs384",
	"Decode JWT token using RS384 (RSA-SHA384) algorithm",
	`Decode and verify a JWT token signed with RS384.

RS384 uses RSA signature with SHA-384 hash for verification. You can
provide either the public key (recommended) or the private key.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key
  jwt-cli decode rs384 --token "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9..." --public-key RS384.key.pub

  # Decode with private key
  jwt-cli decode rs384 --token "$TOKEN" --private-key RS384.key

  # Decode with claims validation and clock skew
  jwt-cli decode rs384 --token "$TOKEN" --public-key RS384.key.pub --validate-claims --clock-skew 30s`,
	cryptojwt.NewRS384DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewRS384DecoderWithPrivateKeyFileAndValidation,
)

var decodeRS512Cmd = createRSDecodeCommand(
	"RS512",
	"rs512",
	"Decode JWT token using RS512 (RSA-SHA512) algorithm",
	`Decode and verify a JWT token signed with RS512.

RS512 uses RSA signature with SHA-512 hash for verification. You can
provide either the public key (recommended) or the private key.

Claims Validation:
  By default, time-based claims (exp, nbf, iat) are not validated. Use
  --validate-claims to enable validation and reject expired tokens.`,
	`  # Decode with public key
  jwt-cli decode rs512 --token "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9..." --public-key RS512.key.pub

  # Decode with private key
  jwt-cli decode rs512 --token "$TOKEN" --private-key RS512.key

  # Decode with claims validation
  jwt-cli decode rs512 --token "$TOKEN" --public-key RS512.key.pub --validate-claims`,
	cryptojwt.NewRS512DecoderWithPublicKeyFileAndValidation,
	cryptojwt.NewRS512DecoderWithPrivateKeyFileAndValidation,
)