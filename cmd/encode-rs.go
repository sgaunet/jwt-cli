package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createRSEncodeCommand(_ /* alg */, use, short, long string, encoder func(string) cryptojwt.Encoder) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Run: func(cmd *cobra.Command, _ []string) {
			if privateKeyFile == "" {
				fmt.Println("private key file is mandatory")
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			if payload == "" {
				fmt.Println("payload is mandatory")
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			
			j := encoder(privateKeyFile)
			t, err := j.Encode(payload)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(t)
		},
	}
}

var encodeRS256Cmd = createRSEncodeCommand(
	"RS256",
	"rs256",
	"encode RS256 JWT token",
	`encode RS256 JWT token`,
	cryptojwt.NewRS256Encoder,
)

var encodeRS384Cmd = createRSEncodeCommand(
	"RS384",
	"rs384",
	"encode RS384 JWT token",
	`encode RS384 JWT token`,
	cryptojwt.NewRS384Encoder,
)

var encodeRS512Cmd = createRSEncodeCommand(
	"RS512",
	"rs512",
	"encode RS512 JWT token",
	`encode RS512 JWT token`,
	cryptojwt.NewRS512Encoder,
)