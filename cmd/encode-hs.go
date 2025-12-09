package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createHSEncodeCommand(_ /* alg */, use, short, long string, encoderWithOpts func([]byte, bool) cryptojwt.EncoderDecoder) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Run: func(cmd *cobra.Command, _ []string) {
			if secret == "" {
				fmt.Fprintln(os.Stderr, "secret is mandatory")
				fmt.Fprintln(os.Stderr, cmd.UsageString())
				os.Exit(1)
			}
			if payload == "" {
				fmt.Fprintln(os.Stderr, "payload is mandatory")
				fmt.Fprintln(os.Stderr, cmd.UsageString())
				os.Exit(1)
			}

			j := encoderWithOpts([]byte(secret), allowWeakSecret)
			t, err := j.Encode(payload)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(t)
		},
	}
}

var encodeHS256Cmd = createHSEncodeCommand(
	"HS256",
	"hs256",
	"encode HS256 JWT token (requires 32+ byte secret)",
	`encode HS256 JWT token

Secret Requirements:
  HS256 requires a minimum of 32 bytes (256 bits) for the secret according to RFC 7518 Section 3.2.
  Use --allow-weak-secret flag to bypass validation for testing purposes only.

Example:
  jwt-cli encode hs256 -s "this-is-a-valid-secret-32byt" -p '{"sub":"user123"}'`,
	cryptojwt.NewHS256EncoderWithOptions,
)

var encodeHS384Cmd = createHSEncodeCommand(
	"HS384",
	"hs384",
	"encode HS384 JWT token (requires 48+ byte secret)",
	`encode HS384 JWT token

Secret Requirements:
  HS384 requires a minimum of 48 bytes (384 bits) for the secret according to RFC 7518 Section 3.2.
  Use --allow-weak-secret flag to bypass validation for testing purposes only.

Example:
  jwt-cli encode hs384 -s "this-is-a-valid-secret-for-hs384-48bytes" -p '{"sub":"user123"}'`,
	cryptojwt.NewHS384EncoderWithOptions,
)

var encodeHS512Cmd = createHSEncodeCommand(
	"HS512",
	"hs512",
	"encode HS512 JWT token (requires 64+ byte secret)",
	`encode HS512 JWT token

Secret Requirements:
  HS512 requires a minimum of 64 bytes (512 bits) for the secret according to RFC 7518 Section 3.2.
  Use --allow-weak-secret flag to bypass validation for testing purposes only.

Example:
  jwt-cli encode hs512 -s "this-is-a-valid-secret-for-hs512-that-meets-64-byte-requirement" -p '{"sub":"user123"}'`,
	cryptojwt.NewHS512EncoderWithOptions,
)