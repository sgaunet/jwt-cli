package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"

	"github.com/spf13/cobra"
)

var encodeHS256Cmd = &cobra.Command{
	Use:   "hs256",
	Short: "encode HS256 JWT token",
	Long:  `encode HS256 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		if secret == "" {
			fmt.Println("secret is mandatory")
			fmt.Println(cmd.UsageString())
			os.Exit(1)
		}
		j := cryptojwt.NewHS256Encoder([]byte(secret))
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var encodeHS384Cmd = &cobra.Command{
	Use:   "hs384",
	Short: "encode HS384 JWT token",
	Long:  `encode HS384 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		if secret == "" {
			fmt.Println("secret is mandatory")
			fmt.Println(cmd.UsageString())
			os.Exit(1)
		}
		j := cryptojwt.NewHS384Encoder([]byte(secret))
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var encodeHS512Cmd = &cobra.Command{
	Use:   "hs512",
	Short: "encode HS512 JWT token",
	Long:  `encode HS512 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		if secret == "" {
			fmt.Println("secret is mandatory")
			fmt.Println(cmd.UsageString())
			os.Exit(1)
		}
		j := cryptojwt.NewHS512Encoder([]byte(secret))
		t, err := j.Encode(payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}
