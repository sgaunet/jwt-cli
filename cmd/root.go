package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var secret, token, payload string
var privateKeyFile, publicKeyFile string

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "jwt-cli",
	Short: "Tool to encode/decode JWT token",
	Long:  `Tool to encode/decode JWT token`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute runs the root command.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(encodeCmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	encodeCmd.PersistentFlags().StringVar(&payload, "p", "", "payload")
	encodeCmd.PersistentFlags().StringVar(&privateKeyFile, "pk", "", "private key file")
	encodeCmd.PersistentFlags().StringVar(&secret, "s", "", "secret")

	// encode subcommands
	encodeCmd.AddCommand(encodeRS256Cmd)
	encodeCmd.AddCommand(encodeRS384Cmd)
	encodeCmd.AddCommand(encodeRS512Cmd)
	encodeCmd.AddCommand(encodeES256Cmd)
	encodeCmd.AddCommand(encodeES384Cmd)
	encodeCmd.AddCommand(encodeES512Cmd)
	encodeCmd.AddCommand(encodeHS256Cmd)
	encodeCmd.AddCommand(encodeHS384Cmd)
	encodeCmd.AddCommand(encodeHS512Cmd)

	rootCmd.AddCommand(decodeCmd)
	decodeCmd.PersistentFlags().StringVar(&privateKeyFile, "pk", "", "private key file")
	decodeCmd.PersistentFlags().StringVar(&publicKeyFile, "pubk", "", "public key file")
	decodeCmd.PersistentFlags().StringVar(&token, "t", "", "token")
	decodeCmd.PersistentFlags().StringVar(&secret, "s", "", "secret")

	// decode subcommands
	decodeCmd.AddCommand(decodeRS256Cmd)
	decodeCmd.AddCommand(decodeRS384Cmd)
	decodeCmd.AddCommand(decodeRS512Cmd)
	decodeCmd.AddCommand(decodeES256Cmd)
	decodeCmd.AddCommand(decodeES384Cmd)
	decodeCmd.AddCommand(decodeES512Cmd)
	decodeCmd.AddCommand(decodeHS256Cmd)
	decodeCmd.AddCommand(decodeHS384Cmd)
	decodeCmd.AddCommand(decodeHS512Cmd)

	// genkeys
	rootCmd.AddCommand(genkeysCmd)
	genkeysCmd.AddCommand(genkeysES256Cmd)
	genkeysCmd.AddCommand(genkeysES384Cmd)
	genkeysCmd.AddCommand(genkeysES512Cmd)
	genkeysCmd.AddCommand(genkeysRS256Cmd)
	genkeysCmd.AddCommand(genkeysRS384Cmd)
	genkeysCmd.AddCommand(genkeysRS512Cmd)
}
