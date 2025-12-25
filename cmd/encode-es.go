package cmd

import (
	"fmt"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createESEncodeCommand(_ /* alg */, use, short, long, example string, encoder func(string) cryptojwt.Encoder) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if privateKeyFile == "" {
				return fmt.Errorf("private key file is mandatory\n\n%s", cmd.UsageString())
			}
			if payload == "" {
				return fmt.Errorf("payload is mandatory\n\n%s", cmd.UsageString())
			}

			j := encoder(privateKeyFile)
			t, err := j.Encode(payload)
			if err != nil {
				return fmt.Errorf("encoding failed: %w", err)
			}
			fmt.Println(t)
			return nil
		},
	}
}

var encodeES256Cmd = createESEncodeCommand(
	"ES256",
	"es256",
	"Encode JWT token using ES256 (ECDSA-SHA256) algorithm",
	`Encode a JSON payload into a JWT token signed with ES256.

ES256 uses Elliptic Curve Digital Signature Algorithm (ECDSA) with SHA-256
hash and P-256 curve. It provides strong security with smaller key sizes
compared to RSA, making it efficient for both computation and bandwidth.

Key Requirements:
  - Private key in PEM format using P-256 curve
  - Generate keys with: jwt-cli genkeys es256`,
	`  # Encode with private key
  jwt-cli encode es256 --payload '{"user":"alice","role":"admin"}' --private-key ecdsa-p256-private.pem

  # Encode with expiration
  jwt-cli encode es256 --payload '{"user":"alice","exp":1735689600}' --private-key ecdsa-p256-private.pem

  # Store token in variable
  TOKEN=$(jwt-cli encode es256 --payload '{"user":"alice"}' --private-key ecdsa-p256-private.pem)`,
	cryptojwt.NewES256Encoder,
)

var encodeES384Cmd = createESEncodeCommand(
	"ES384",
	"es384",
	"Encode JWT token using ES384 (ECDSA-SHA384) algorithm",
	`Encode a JSON payload into a JWT token signed with ES384.

ES384 uses ECDSA with SHA-384 hash and P-384 curve, providing higher
security strength than ES256.

Key Requirements:
  - Private key in PEM format using P-384 curve
  - Generate keys with: jwt-cli genkeys es384`,
	`  # Encode with private key
  jwt-cli encode es384 --payload '{"user":"alice","role":"admin"}' --private-key jwtES384key.pem

  # Store token in variable
  TOKEN=$(jwt-cli encode es384 --payload '{"user":"alice"}' --private-key jwtES384key.pem)`,
	cryptojwt.NewES384Encoder,
)

var encodeES512Cmd = createESEncodeCommand(
	"ES512",
	"es512",
	"Encode JWT token using ES512 (ECDSA-SHA512) algorithm",
	`Encode a JSON payload into a JWT token signed with ES512.

ES512 uses ECDSA with SHA-512 hash and P-521 curve, providing the highest
security strength in the ES family.

Key Requirements:
  - Private key in PEM format using P-521 curve
  - Generate keys with: jwt-cli genkeys es512`,
	`  # Encode with private key
  jwt-cli encode es512 --payload '{"user":"alice","role":"admin"}' --private-key ecdsa-p521-private.pem

  # Store token in variable
  TOKEN=$(jwt-cli encode es512 --payload '{"user":"alice"}' --private-key ecdsa-p521-private.pem)`,
	cryptojwt.NewES512Encoder,
)