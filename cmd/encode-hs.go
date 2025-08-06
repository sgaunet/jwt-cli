package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createHSEncodeCommand(_ /* alg */, use, short, long string, encoder func([]byte) cryptojwt.EncoderDecoder) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Run: func(cmd *cobra.Command, _ []string) {
			if secret == "" {
				fmt.Println("secret is mandatory")
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			if payload == "" {
				fmt.Println("payload is mandatory")
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			
			j := encoder([]byte(secret))
			t, err := j.Encode(payload)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(t)
		},
	}
}

var encodeHS256Cmd = createHSEncodeCommand(
	"HS256",
	"hs256",
	"encode HS256 JWT token",
	`encode HS256 JWT token`,
	cryptojwt.NewHS256Encoder,
)

var encodeHS384Cmd = createHSEncodeCommand(
	"HS384",
	"hs384",
	"encode HS384 JWT token",
	`encode HS384 JWT token`,
	cryptojwt.NewHS384Encoder,
)

var encodeHS512Cmd = createHSEncodeCommand(
	"HS512",
	"hs512",
	"encode HS512 JWT token",
	`encode HS512 JWT token`,
	cryptojwt.NewHS512Encoder,
)