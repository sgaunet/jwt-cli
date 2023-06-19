package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var secret, token, payload, method string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "jwt-cli",
	Short: "Tool to encode/decode JWT token",
	Long:  `Tool to encode/decode JWT token`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&secret, "s", "", "JWT secret")
	rootCmd.PersistentFlags().StringVar(&method, "m", "", "Signing Method ")

	rootCmd.AddCommand(encodeCmd)
	encodeCmd.Flags().StringVar(&payload, "p", "", "payload")
	rootCmd.AddCommand(decodeCmd)
	decodeCmd.Flags().StringVar(&token, "t", "", "token")
	rootCmd.AddCommand(methodsCmd)
}
