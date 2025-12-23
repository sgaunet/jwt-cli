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
			if privateKeyFile == "" && publicKeyFile == "" {
				return fmt.Errorf("private key file or public key file is mandatory\n\n%s", cmd.UsageString())
			}
			if token == "" {
				return fmt.Errorf("token is mandatory\n\n%s", cmd.UsageString())
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
  jwt-cli decode es256 --token "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..." --public-key-file ecdsa-p256-public.pem

  # Decode with private key
  jwt-cli decode es256 --token "$TOKEN" --private-key-file ecdsa-p256-private.pem

  # Decode and extract specific field
  jwt-cli decode es256 --token "$TOKEN" --public-key-file ecdsa-p256-public.pem | jq -r '.user'`,
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
  jwt-cli decode es384 --token "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9..." --public-key-file jwtES384pubkey.pem

  # Decode with private key
  jwt-cli decode es384 --token "$TOKEN" --private-key-file jwtES384key.pem`,
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
  jwt-cli decode es512 --token "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9..." --public-key-file ecdsa-p521-public.pem

  # Decode with private key
  jwt-cli decode es512 --token "$TOKEN" --private-key-file ecdsa-p521-private.pem`,
	cryptojwt.NewES512DecoderWithPublicKeyFile,
	cryptojwt.NewES512DecoderWithPrivateKeyFile,
)