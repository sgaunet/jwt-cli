package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

var encodeES256Cmd = &cobra.Command{
	Use:   "es256",
	Short: "encode ES256 JWT token",
	Long:  `encode ES256 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
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
		j := cryptojwt.NewES256Encoder(privateKeyFile)
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var encodeES384Cmd = &cobra.Command{
	Use:   "es384",
	Short: "encode ES384 JWT token",
	Long:  `encode ES384 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
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
		j := cryptojwt.NewES384Encoder(privateKeyFile)
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var encodeES512Cmd = &cobra.Command{
	Use:   "es512",
	Short: "encode ES512 JWT token",
	Long:  `encode ES512 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
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
		j := cryptojwt.NewES512Encoder(privateKeyFile)
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}
