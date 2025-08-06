// Package cmd contains the command-line interface commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

//nolint:dupl // Similar structure needed for different algorithms
func createESDecodeCommand(_ /* alg */, use string, pubKeyDecoder, privKeyDecoder func(string) cryptojwt.Decoder) *cobra.Command {
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

var decodeES256Cmd = createESDecodeCommand(
	"ES256",
	"es256",
	cryptojwt.NewES256DecoderWithPublicKeyFile,
	cryptojwt.NewES256DecoderWithPrivateKeyFile,
)

var decodeES384Cmd = createESDecodeCommand(
	"ES384",
	"es384",
	cryptojwt.NewES384DecoderWithPublicKeyFile,
	cryptojwt.NewES384DecoderWithPrivateKeyFile,
)

var decodeES512Cmd = createESDecodeCommand(
	"ES512",
	"es512",
	cryptojwt.NewES512DecoderWithPublicKeyFile,
	cryptojwt.NewES512DecoderWithPrivateKeyFile,
)