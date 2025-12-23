package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createRSEncodeCommand(_ /* alg */, use, short, long, example string, encoder func(string) cryptojwt.Encoder) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		Run: func(cmd *cobra.Command, _ []string) {
			if privateKeyFile == "" {
				fmt.Fprintln(os.Stderr, "private key file is mandatory")
				fmt.Fprintln(os.Stderr, cmd.UsageString())
				os.Exit(1)
			}
			if payload == "" {
				fmt.Fprintln(os.Stderr, "payload is mandatory")
				fmt.Fprintln(os.Stderr, cmd.UsageString())
				os.Exit(1)
			}

			j := encoder(privateKeyFile)
			t, err := j.Encode(payload)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(t)
		},
	}
}

var encodeRS256Cmd = createRSEncodeCommand(
	"RS256",
	"rs256",
	"Encode JWT token using RS256 (RSA-SHA256) algorithm",
	`Encode a JSON payload into a JWT token signed with RS256.

RS256 uses RSA signature with SHA-256 hash. It requires a private key
for signing and the corresponding public key for verification. This is
an asymmetric algorithm suitable for scenarios where the token issuer
and validator are different entities.

Key Requirements:
  - Private key in PEM format (typically .pem or .key file)
  - Minimum 2048-bit RSA key recommended for security
  - Generate keys with: jwt-cli genkeys rs256`,
	`  # Encode with private key
  jwt-cli encode rs256 --payload '{"user":"alice","role":"admin"}' --private-key-file RS256.key

  # Encode with expiration
  jwt-cli encode rs256 --payload '{"user":"alice","exp":1735689600}' --private-key-file RS256.key

  # Encode from file and store token
  TOKEN=$(jwt-cli encode rs256 --payload "$(cat payload.json)" --private-key-file RS256.key)`,
	cryptojwt.NewRS256Encoder,
)

var encodeRS384Cmd = createRSEncodeCommand(
	"RS384",
	"rs384",
	"Encode JWT token using RS384 (RSA-SHA384) algorithm",
	`Encode a JSON payload into a JWT token signed with RS384.

RS384 uses RSA signature with SHA-384 hash. It requires a private key
for signing and the corresponding public key for verification.

Key Requirements:
  - Private key in PEM format
  - Minimum 2048-bit RSA key recommended
  - Generate keys with: jwt-cli genkeys rs384`,
	`  # Encode with private key
  jwt-cli encode rs384 --payload '{"user":"alice","role":"admin"}' --private-key-file RS384.key

  # Store token in variable
  TOKEN=$(jwt-cli encode rs384 --payload '{"user":"alice"}' --private-key-file RS384.key)`,
	cryptojwt.NewRS384Encoder,
)

var encodeRS512Cmd = createRSEncodeCommand(
	"RS512",
	"rs512",
	"Encode JWT token using RS512 (RSA-SHA512) algorithm",
	`Encode a JSON payload into a JWT token signed with RS512.

RS512 uses RSA signature with SHA-512 hash. It requires a private key
for signing and the corresponding public key for verification.

Key Requirements:
  - Private key in PEM format
  - Minimum 2048-bit RSA key recommended
  - Generate keys with: jwt-cli genkeys rs512`,
	`  # Encode with private key
  jwt-cli encode rs512 --payload '{"user":"alice","role":"admin"}' --private-key-file RS512.key

  # Store token in variable
  TOKEN=$(jwt-cli encode rs512 --payload '{"user":"alice"}' --private-key-file RS512.key)`,
	cryptojwt.NewRS512Encoder,
)