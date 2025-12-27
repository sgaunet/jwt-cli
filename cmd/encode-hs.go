package cmd

import (
	"fmt"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createHSEncodeCommand(_ /* alg */, use, short, long, example string, encoderWithOpts func([]byte, bool) cryptojwt.EncoderDecoder) *cobra.Command {
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
			payload, _ := cmd.Flags().GetString("payload")
			if payload == "" {
				payload, _ = cmd.Flags().GetString("p") // Check deprecated flag
			}
			allowWeakSecret, _ := cmd.Flags().GetBool("allow-weak-secret")

			if secret == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: secret is required

The secret is used to sign and verify HMAC-based JWT tokens. It must be kept confidential.

Example usage:
  jwt-cli encode %s --secret "your-secret-key" --payload '{"user":"alice","role":"admin"}'

Tip: Use a strong secret. HS256 requires at least 32 bytes, HS384 requires 48 bytes, HS512 requires 64 bytes.
     Use --allow-weak-secret flag only for testing purposes.`, use)
			}
			if payload == "" {
				//nolint:revive,staticcheck // User-facing error message with proper formatting
				return fmt.Errorf(`Error: payload is required

The payload contains the claims (data) to be encoded in the JWT token.

Example usage:
  jwt-cli encode %s --secret "your-secret-key" --payload '{"user":"alice","role":"admin"}'

Tip: Payload must be valid JSON. Common claims include 'sub' (subject), 'exp' (expiration), 'iat' (issued at).`, use)
			}

			j := encoderWithOpts([]byte(secret), allowWeakSecret)
			t, err := j.Encode(payload)
			if err != nil {
				return fmt.Errorf("encoding failed: %w", err)
			}
			fmt.Println(t)
			return nil
		},
	}
}

var encodeHS256Cmd = createHSEncodeCommand(
	"HS256",
	"hs256",
	"Encode JWT token using HS256 (HMAC-SHA256) algorithm",
	`Encode a JSON payload into a JWT token signed with HS256.

HS256 uses HMAC with SHA-256 for signing. It requires a shared secret
that must be kept confidential. The same secret is used for both
encoding and decoding.

Secret Requirements:
  HS256 requires a minimum of 32 bytes (256 bits) for the secret according
  to RFC 7518 Section 3.2. Use --allow-weak-secret flag to bypass validation
  for testing purposes only.`,
	`  # Encode a simple payload
  jwt-cli encode hs256 --payload '{"user":"alice","role":"admin"}' --secret "my-32-byte-secret-key-for-hs256"

  # Encode with expiration (Unix timestamp)
  jwt-cli encode hs256 --payload '{"user":"alice","exp":1735689600}' --secret "my-32-byte-secret-key-for-hs256"

  # Encode from file
  jwt-cli encode hs256 --payload "$(cat payload.json)" --secret "my-32-byte-secret-key-for-hs256"

  # Store token in variable
  TOKEN=$(jwt-cli encode hs256 --payload '{"user":"alice"}' --secret "my-32-byte-secret-key-for-hs256")`,
	cryptojwt.NewHS256EncoderWithOptions,
)

var encodeHS384Cmd = createHSEncodeCommand(
	"HS384",
	"hs384",
	"Encode JWT token using HS384 (HMAC-SHA384) algorithm",
	`Encode a JSON payload into a JWT token signed with HS384.

HS384 uses HMAC with SHA-384 for signing. It requires a shared secret
that must be kept confidential. The same secret is used for both
encoding and decoding.

Secret Requirements:
  HS384 requires a minimum of 48 bytes (384 bits) for the secret according
  to RFC 7518 Section 3.2. Use --allow-weak-secret flag to bypass validation
  for testing purposes only.`,
	`  # Encode a simple payload
  jwt-cli encode hs384 --payload '{"user":"alice","role":"admin"}' --secret "my-48-byte-secret-key-for-hs384-authentication"

  # Encode with expiration
  jwt-cli encode hs384 --payload '{"user":"alice","exp":1735689600}' --secret "my-48-byte-secret-key-for-hs384-authentication"

  # Store token in variable
  TOKEN=$(jwt-cli encode hs384 --payload '{"user":"alice"}' --secret "my-48-byte-secret-key-for-hs384-authentication")`,
	cryptojwt.NewHS384EncoderWithOptions,
)

var encodeHS512Cmd = createHSEncodeCommand(
	"HS512",
	"hs512",
	"Encode JWT token using HS512 (HMAC-SHA512) algorithm",
	`Encode a JSON payload into a JWT token signed with HS512.

HS512 uses HMAC with SHA-512 for signing. It requires a shared secret
that must be kept confidential. The same secret is used for both
encoding and decoding.

Secret Requirements:
  HS512 requires a minimum of 64 bytes (512 bits) for the secret according
  to RFC 7518 Section 3.2. Use --allow-weak-secret flag to bypass validation
  for testing purposes only.`,
	`  # Encode a simple payload
  jwt-cli encode hs512 --payload '{"user":"alice","role":"admin"}' --secret "my-64-byte-secret-key-for-hs512-that-meets-minimum-requirement"

  # Encode with expiration
  jwt-cli encode hs512 --payload '{"user":"alice","exp":1735689600}' --secret "my-64-byte-secret-key-for-hs512-that-meets-minimum-requirement"

  # Store token in variable
  TOKEN=$(jwt-cli encode hs512 --payload '{"user":"alice"}' --secret "my-64-byte-secret-key-for-hs512-that-meets-minimum-requirement")`,
	cryptojwt.NewHS512EncoderWithOptions,
)