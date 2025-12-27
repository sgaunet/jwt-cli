package cmd

import (
	"errors"
	"fmt"

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
		RunE: func(cmd *cobra.Command, _ []string) error {
			privateKeyFile, _ := cmd.Flags().GetString("private-key")
			if privateKeyFile == "" {
				privateKeyFile, _ = cmd.Flags().GetString("pk") // Check deprecated flag
			}
			payload, _ := cmd.Flags().GetString("payload")
			if payload == "" {
				payload, _ = cmd.Flags().GetString("p") // Check deprecated flag
			}

			if privateKeyFile == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: private key file is required

Provide the path to your RSA private key file in PEM format for signing the JWT token.

Example usage:
  jwt-cli encode %s --private-key ./keys/private.pem --payload '{"sub":"1234567890","name":"Alice"}'

Generate keys with:
  jwt-cli genkeys %s

Tip: Keep your private key secure and never share it. Use minimum 2048-bit RSA keys.`, use, use)
			}
			if payload == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: payload is required

The payload contains the claims (data) to be encoded in the JWT token.

Example usage:
  jwt-cli encode %s --private-key ./keys/private.pem --payload '{"sub":"1234567890","name":"Alice"}'

Tip: Payload must be valid JSON. Common claims include 'sub' (subject), 'exp' (expiration), 'iat' (issued at).`, use)
			}

			j := encoder(privateKeyFile)
			t, err := j.Encode(payload)
			if err != nil {
				errMsg := fmt.Sprintf("encoding failed: %v", err)
				output(CommandOutput{Success: false, Error: errMsg})
				return errors.New(errMsg)
			}
			output(CommandOutput{Success: true, Token: t})
			return nil
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
  jwt-cli encode rs256 --payload '{"user":"alice","role":"admin"}' --private-key RS256.key

  # Encode with expiration
  jwt-cli encode rs256 --payload '{"user":"alice","exp":1735689600}' --private-key RS256.key

  # Encode from file and store token
  TOKEN=$(jwt-cli encode rs256 --payload "$(cat payload.json)" --private-key RS256.key)`,
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
  jwt-cli encode rs384 --payload '{"user":"alice","role":"admin"}' --private-key RS384.key

  # Store token in variable
  TOKEN=$(jwt-cli encode rs384 --payload '{"user":"alice"}' --private-key RS384.key)`,
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
  jwt-cli encode rs512 --payload '{"user":"alice","role":"admin"}' --private-key RS512.key

  # Store token in variable
  TOKEN=$(jwt-cli encode rs512 --payload '{"user":"alice"}' --private-key RS512.key)`,
	cryptojwt.NewRS512Encoder,
)