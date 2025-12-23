package cmd

import (
	"fmt"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createHSDecodeCommand(_ /* alg */, use, short, long, example string, decoderWithOpts func([]byte, bool) cryptojwt.EncoderDecoder) *cobra.Command {
	return &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if secret == "" {
				return fmt.Errorf("secret is mandatory\n\n%s", cmd.UsageString())
			}
			if token == "" {
				return fmt.Errorf("token is mandatory\n\n%s", cmd.UsageString())
			}

			j := decoderWithOpts([]byte(secret), allowWeakSecret)
			t, err := j.Decode(token)
			if err != nil {
				return fmt.Errorf("decoding failed: %w", err)
			}
			fmt.Println(t)
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
  for testing purposes only.`,
	`  # Decode a token
  jwt-cli decode hs256 --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --secret "my-32-byte-secret-key-for-hs256"

  # Decode token from variable
  jwt-cli decode hs256 --token "$TOKEN" --secret "my-32-byte-secret-key-for-hs256"

  # Decode and extract specific field with jq
  jwt-cli decode hs256 --token "$TOKEN" --secret "my-32-byte-secret-key-for-hs256" | jq -r '.user'`,
	cryptojwt.NewHS256DecoderWithOptions,
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
  for testing purposes only.`,
	`  # Decode a token
  jwt-cli decode hs384 --token "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9..." --secret "my-48-byte-secret-key-for-hs384-authentication"

  # Decode token from variable
  jwt-cli decode hs384 --token "$TOKEN" --secret "my-48-byte-secret-key-for-hs384-authentication"`,
	cryptojwt.NewHS384DecoderWithOptions,
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
  for testing purposes only.`,
	`  # Decode a token
  jwt-cli decode hs512 --token "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..." --secret "my-64-byte-secret-key-for-hs512-that-meets-minimum-requirement"

  # Decode token from variable
  jwt-cli decode hs512 --token "$TOKEN" --secret "my-64-byte-secret-key-for-hs512-that-meets-minimum-requirement"`,
	cryptojwt.NewHS512DecoderWithOptions,
)