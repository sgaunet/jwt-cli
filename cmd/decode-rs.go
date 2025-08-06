package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createRSDecodeCommand(_ /* alg */, use string, pubKeyDecoder, privKeyDecoder func(string) cryptojwt.Decoder) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: "decode JWT token",
		Long:  `decode JWT token`,
		Run: func(cmd *cobra.Command, _ []string) {
			if privateKeyFile == "" && publicKeyFile == "" {
				fmt.Println("private key file or public key file is mandatory")
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}
			if token == "" {
				fmt.Println("token is mandatory")
				fmt.Println(cmd.UsageString())
				os.Exit(1)
			}

			var j cryptojwt.Decoder
			if publicKeyFile != "" {
				j = pubKeyDecoder(publicKeyFile)
			} else {
				j = privKeyDecoder(privateKeyFile)
			}
			
			t, err := j.Decode(token)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			fmt.Println(t)
		},
	}
}

var decodeRS256Cmd = createRSDecodeCommand(
	"RS256",
	"rs256",
	cryptojwt.NewRS256DecoderWithPublicKeyFile,
	cryptojwt.NewRS256DecoderWithPrivateKeyFile,
)

var decodeRS384Cmd = createRSDecodeCommand(
	"RS384",
	"rs384",
	cryptojwt.NewRS384DecoderWithPublicKeyFile,
	cryptojwt.NewRS384DecoderWithPrivateKeyFile,
)

var decodeRS512Cmd = createRSDecodeCommand(
	"RS512",
	"rs512",
	cryptojwt.NewRS512DecoderWithPublicKeyFile,
	cryptojwt.NewRS512DecoderWithPrivateKeyFile,
)