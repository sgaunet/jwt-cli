package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

var decodeES256Cmd = &cobra.Command{
	Use:   "es256",
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
			j = cryptojwt.NewES256DecoderWithPublicKeyFile(publicKeyFile)
		} else {
			j = cryptojwt.NewES256DecoderWithPrivateKeyFile(privateKeyFile)
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var decodeES384Cmd = &cobra.Command{
	Use:   "es384",
	Short: "decode es384 JWT token",
	Long:  `decode es384 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var j cryptojwt.Decoder
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
			j = cryptojwt.NewES384DecoderWithPublicKeyFile(publicKeyFile)
		} else {
			j = cryptojwt.NewES384DecoderWithPrivateKeyFile(privateKeyFile)
		}
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var decodeES512Cmd = &cobra.Command{
	Use:   "es512",
	Short: "decode es512 JWT token",
	Long:  `decode es512 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var j cryptojwt.Decoder
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
			j = cryptojwt.NewES512DecoderWithPublicKeyFile(publicKeyFile)
		} else {
			j = cryptojwt.NewES512DecoderWithPrivateKeyFile(privateKeyFile)
		}
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}
