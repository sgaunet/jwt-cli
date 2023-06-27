package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/cryptojwt"

	"github.com/spf13/cobra"
)

// encodeCmd represents the encode command
var decodeHS256Cmd = &cobra.Command{
	Use:   "hs256",
	Short: "decode HS256 JWT token",
	Long:  `decode HS256 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
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
		j := cryptojwt.NewHS256Decoder([]byte(secret))
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var decodeHS384Cmd = &cobra.Command{
	Use:   "hs384",
	Short: "decode HS384 JWT token",
	Long:  `decode HS384 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
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
		j := cryptojwt.NewHS384Decoder([]byte(secret))
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}

var decodeHS512Cmd = &cobra.Command{
	Use:   "hs512",
	Short: "decode HS512 JWT token",
	Long:  `decode HS512 JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
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
		j := cryptojwt.NewHS512Decoder([]byte(secret))
		t, err := j.Decode(token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}
