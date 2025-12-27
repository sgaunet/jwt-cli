package cmd

import (
	"fmt"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createESDecodeCommand(_ /* alg */, use, short, long, example string, pubKeyDecoder, privKeyDecoder func(string) cryptojwt.Decoder) *cobra.Command {
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

			if privateKeyFile == "" && publicKeyFile == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: key file is required

Provide either a public key file (recommended) or private key file in PEM format to verify the JWT token.

Example usage with public key (recommended):
  jwt-cli decode %s --token "eyJhbGci..." --public-key ./keys/ec-public.pem

Example usage with private key:
  jwt-cli decode %s --token "eyJhbGci..." --private-key ./keys/ec-private.pem

Tip: Use the public key for verification to follow asymmetric cryptography best practices.
     The key must match the one used to encode the token.
     ES256 uses P-256 curve, ES384 uses P-384, ES512 uses P-521.`, use, use)
			}
			if token == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: token is required

Provide the JWT token string to decode and verify.

Example usage:
  jwt-cli decode %s --token "eyJhbGci..." --public-key ./keys/ec-public.pem
  jwt-cli decode %s --token "$TOKEN" --public-key ./keys/ec-public.pem

Tip: The token is the three-part string (header.payload.signature) produced by the encode command.`, use, use)
			}

			var j cryptojwt.Decoder
			if publicKeyFile != "" {
				j = pubKeyDecoder(publicKeyFile)
			} else {
				j = privKeyDecoder(privateKeyFile)
			}

			t, err := j.Decode(token)
			if err != nil {
				return fmt.Errorf("decoding failed: %w", err)
			}
			fmt.Println(t)
			return nil
		},
	}
}

var decodeES256Cmd = createESDecodeCommand(
	"ES256",
	"es256",
	"Decode JWT token using ES256 (ECDSA-SHA256) algorithm",
	`Decode and verify a JWT token signed with ES256.

ES256 uses ECDSA with SHA-256 hash and P-256 curve for verification.
You can provide either the public key (recommended) or the private key.

Key Requirements:
  - Public or private key in PEM format using P-256 curve
  - Key must match the one used for encoding`,
	`  # Decode with public key (recommended)
  jwt-cli decode es256 --token "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..." --public-key ecdsa-p256-public.pem

  # Decode with private key
  jwt-cli decode es256 --token "$TOKEN" --private-key ecdsa-p256-private.pem

  # Decode and extract specific field
  jwt-cli decode es256 --token "$TOKEN" --public-key ecdsa-p256-public.pem | jq -r '.user'`,
	cryptojwt.NewES256DecoderWithPublicKeyFile,
	cryptojwt.NewES256DecoderWithPrivateKeyFile,
)

var decodeES384Cmd = createESDecodeCommand(
	"ES384",
	"es384",
	"Decode JWT token using ES384 (ECDSA-SHA384) algorithm",
	`Decode and verify a JWT token signed with ES384.

ES384 uses ECDSA with SHA-384 hash and P-384 curve for verification.
You can provide either the public key (recommended) or the private key.`,
	`  # Decode with public key
  jwt-cli decode es384 --token "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9..." --public-key jwtES384pubkey.pem

  # Decode with private key
  jwt-cli decode es384 --token "$TOKEN" --private-key jwtES384key.pem`,
	cryptojwt.NewES384DecoderWithPublicKeyFile,
	cryptojwt.NewES384DecoderWithPrivateKeyFile,
)

var decodeES512Cmd = createESDecodeCommand(
	"ES512",
	"es512",
	"Decode JWT token using ES512 (ECDSA-SHA512) algorithm",
	`Decode and verify a JWT token signed with ES512.

ES512 uses ECDSA with SHA-512 hash and P-521 curve for verification.
You can provide either the public key (recommended) or the private key.`,
	`  # Decode with public key
  jwt-cli decode es512 --token "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9..." --public-key ecdsa-p521-public.pem

  # Decode with private key
  jwt-cli decode es512 --token "$TOKEN" --private-key ecdsa-p521-private.pem`,
	cryptojwt.NewES512DecoderWithPublicKeyFile,
	cryptojwt.NewES512DecoderWithPrivateKeyFile,
)