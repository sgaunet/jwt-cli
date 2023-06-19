package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/jwt-cli/pkg/app"

	"github.com/spf13/cobra"
)

// encodeCmd represents the encode command
var encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "encode JWT token",
	Long:  `encode JWT token`,
	Run: func(cmd *cobra.Command, args []string) {
		err := CheckArguments(secret, token, method)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		t, err := app.EncodeJWT([]byte(secret), method, payload)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(t)
	},
}
