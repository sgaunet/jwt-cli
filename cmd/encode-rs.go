package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"
	"github.com/spf13/cobra"
)

var encodeRS256Cmd = &cobra.Command{
	Use:   "rs256",
	Short: "encode RS256 JWT token",
	Long:  `encode RS256 JWT token`,
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
		j := cryptojwt.NewRS256Encoder(privateKeyFile)
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var encodeRS384Cmd = &cobra.Command{
	Use:   "rs384",
	Short: "encode RS384 JWT token",
	Long:  `encode RS384 JWT token`,
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
		j := cryptojwt.NewRS384Encoder(privateKeyFile)
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var encodeRS512Cmd = &cobra.Command{
	Use:   "rs512",
	Short: "encode RS512 JWT token",
	Long:  `encode RS512 JWT token`,
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

		j := cryptojwt.NewRS512Encoder(privateKeyFile)
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}
