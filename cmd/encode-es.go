package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createESEncodeCommand(_ /* alg */, use, short, long string, encoder func(string) cryptojwt.Encoder) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
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

var encodeES256Cmd = createESEncodeCommand(
	"ES256",
	"es256",
	"encode ES256 JWT token",
	`encode ES256 JWT token`,
	cryptojwt.NewES256Encoder,
)

var encodeES384Cmd = createESEncodeCommand(
	"ES384",
	"es384",
	"encode ES384 JWT token",
	`encode ES384 JWT token`,
	cryptojwt.NewES384Encoder,
)

var encodeES512Cmd = createESEncodeCommand(
	"ES512",
	"es512",
	"encode ES512 JWT token",
	`encode ES512 JWT token`,
	cryptojwt.NewES512Encoder,
)