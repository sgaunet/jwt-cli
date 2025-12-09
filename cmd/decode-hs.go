package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createHSDecodeCommand(_ /* alg */, use, short, long string, decoderWithOpts func([]byte, bool) cryptojwt.EncoderDecoder) *cobra.Command {
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
			if token == "" {
				fmt.Fprintln(os.Stderr, "token is mandatory")
				fmt.Fprintln(os.Stderr, cmd.UsageString())
				os.Exit(1)
			}

			j := decoderWithOpts([]byte(secret), allowWeakSecret)
			t, err := j.Decode(token)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println(t)
		},
	}
}

var decodeHS256Cmd = createHSDecodeCommand(
	"HS256",
	"hs256",
	"decode HS256 JWT token (requires 32+ byte secret)",
	`decode HS256 JWT token

Secret Requirements:
  HS256 requires a minimum of 32 bytes (256 bits) for the secret according to RFC 7518 Section 3.2.
  Use --allow-weak-secret flag to bypass validation for testing purposes only.

Example:
  jwt-cli decode hs256 -s "this-is-a-valid-secret-32byt" -t "eyJhbGc..."`,
	cryptojwt.NewHS256DecoderWithOptions,
)

var decodeHS384Cmd = createHSDecodeCommand(
	"HS384",
	"hs384",
	"decode HS384 JWT token (requires 48+ byte secret)",
	`decode HS384 JWT token

Secret Requirements:
  HS384 requires a minimum of 48 bytes (384 bits) for the secret according to RFC 7518 Section 3.2.
  Use --allow-weak-secret flag to bypass validation for testing purposes only.

Example:
  jwt-cli decode hs384 -s "this-is-a-valid-secret-for-hs384-48bytes" -t "eyJhbGc..."`,
	cryptojwt.NewHS384DecoderWithOptions,
)

var decodeHS512Cmd = createHSDecodeCommand(
	"HS512",
	"hs512",
	"decode HS512 JWT token (requires 64+ byte secret)",
	`decode HS512 JWT token

Secret Requirements:
  HS512 requires a minimum of 64 bytes (512 bits) for the secret according to RFC 7518 Section 3.2.
  Use --allow-weak-secret flag to bypass validation for testing purposes only.

Example:
  jwt-cli decode hs512 -s "this-is-a-valid-secret-for-hs512-that-meets-64-byte-requirement" -t "eyJhbGc..."`,
	cryptojwt.NewHS512DecoderWithOptions,
)