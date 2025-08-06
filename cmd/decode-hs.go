package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createHSDecodeCommand(_ /* alg */, use, short, long string, decoder func([]byte) cryptojwt.EncoderDecoder) *cobra.Command {
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
			if token == "" {
				fmt.Println("token is mandatory")
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			
			j := decoder([]byte(secret))
			t, err := j.Decode(token)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(t)
		},
	}
}

var decodeHS256Cmd = createHSDecodeCommand(
	"HS256",
	"hs256",
	"decode HS256 JWT token",
	`decode HS256 JWT token`,
	cryptojwt.NewHS256Decoder,
)

var decodeHS384Cmd = createHSDecodeCommand(
	"HS384",
	"hs384",
	"decode HS384 JWT token",
	`decode HS384 JWT token`,
	cryptojwt.NewHS384Decoder,
)

var decodeHS512Cmd = createHSDecodeCommand(
	"HS512",
	"hs512",
	"decode HS512 JWT token",
	`decode HS512 JWT token`,
	cryptojwt.NewHS512Decoder,
)