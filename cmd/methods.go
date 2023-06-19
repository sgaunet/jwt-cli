package cmd

import (
	"os"

	"github.com/sgaunet/jwt-cli/pkg/app"

	"github.com/spf13/cobra"
)

// methodsCmd represents the methods command
var methodsCmd = &cobra.Command{
	Use:   "methods",
	Short: "print list of signing methods",
	Long:  `print list of signing methods`,
	Run: func(cmd *cobra.Command, args []string) {
		app.PrintMethod(os.Stdout)
	},
}
