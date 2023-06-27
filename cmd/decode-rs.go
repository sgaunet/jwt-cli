package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

var decodeRS256Cmd = &cobra.Command{
	Use:   "rs256",
	Short: "decode JWT token",
	Long:  `decode JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			j   cryptojwt.Decoder
			err error
		)
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

		if publicKeyFile != "" {
			j = cryptojwt.NewRS256DecoderWithPublicKeyFile(publicKeyFile)
		} else {
			j = cryptojwt.NewRS256DecoderWithPrivateKeyFile(privateKeyFile)
		}
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var decodeRS384Cmd = &cobra.Command{
	Use:   "rs384",
	Short: "decode JWT token",
	Long:  `decode JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			j   cryptojwt.Decoder
			err error
		)
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

		if publicKeyFile != "" {
			j = cryptojwt.NewRS384DecoderWithPublicKeyFile(publicKeyFile)
		} else {
			j = cryptojwt.NewRS384DecoderWithPrivateKeyFile(privateKeyFile)
		}
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var decodeRS512Cmd = &cobra.Command{
	Use:   "rs512",
	Short: "decode JWT token",
	Long:  `decode JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			j   cryptojwt.Decoder
			err error
		)
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
		if publicKeyFile != "" {
			j = cryptojwt.NewRS512DecoderWithPublicKeyFile(publicKeyFile)
		} else {
			j = cryptojwt.NewRS512DecoderWithPrivateKeyFile(privateKeyFile)
		}
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}
