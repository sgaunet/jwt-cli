package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createRSDecodeCommand(_ /* alg */, use, short, long, example string, pubKeyDecoder, privKeyDecoder func(string) cryptojwt.Decoder) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, _ []string) {
			if privateKeyFile == "" && publicKeyFile == "" {
				fmt.Fprintln(os.Stderr, "private key file or public key file is mandatory")
				fmt.Fprintln(os.Stderr, cmd.UsageString())
				os.Exit(1)
			}
			if token == "" {
				fmt.Fprintln(os.Stderr, "token is mandatory")
				fmt.Fprintln(os.Stderr, cmd.UsageString())
				os.Exit(1)
			}

			var j cryptojwt.Decoder
			if publicKeyFile != "" {
				j = pubKeyDecoder(publicKeyFile)
			} else {
				j = privKeyDecoder(privateKeyFile)
			}

			t, err := j.Decode(token)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(t)
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
  - Key must match the one used for encoding`,
	`  # Decode with public key (recommended)
  jwt-cli decode rs256 --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." --public-key-file RS256.key.pub

  # Decode with private key
  jwt-cli decode rs256 --token "$TOKEN" --private-key-file RS256.key

  # Decode and extract specific field
  jwt-cli decode rs256 --token "$TOKEN" --public-key-file RS256.key.pub | jq -r '.user'`,
	cryptojwt.NewRS256DecoderWithPublicKeyFile,
	cryptojwt.NewRS256DecoderWithPrivateKeyFile,
)

var decodeRS384Cmd = createRSDecodeCommand(
	"RS384",
	"rs384",
	"Decode JWT token using RS384 (RSA-SHA384) algorithm",
	`Decode and verify a JWT token signed with RS384.

RS384 uses RSA signature with SHA-384 hash for verification. You can
provide either the public key (recommended) or the private key.`,
	`  # Decode with public key
  jwt-cli decode rs384 --token "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9..." --public-key-file RS384.key.pub

  # Decode with private key
  jwt-cli decode rs384 --token "$TOKEN" --private-key-file RS384.key`,
	cryptojwt.NewRS384DecoderWithPublicKeyFile,
	cryptojwt.NewRS384DecoderWithPrivateKeyFile,
)

var decodeRS512Cmd = createRSDecodeCommand(
	"RS512",
	"rs512",
	"Decode JWT token using RS512 (RSA-SHA512) algorithm",
	`Decode and verify a JWT token signed with RS512.

RS512 uses RSA signature with SHA-512 hash for verification. You can
provide either the public key (recommended) or the private key.`,
	`  # Decode with public key
  jwt-cli decode rs512 --token "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9..." --public-key-file RS512.key.pub

  # Decode with private key
  jwt-cli decode rs512 --token "$TOKEN" --private-key-file RS512.key`,
	cryptojwt.NewRS512DecoderWithPublicKeyFile,
	cryptojwt.NewRS512DecoderWithPrivateKeyFile,
)