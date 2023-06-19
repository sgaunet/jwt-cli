package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/app"
	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "decode JWT token",
	Long:  `decode JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		err := CheckArguments(secret, token, method)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		payload, err := app.DecodeJWT([]byte(secret), method, token)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(payload)
	},
}
