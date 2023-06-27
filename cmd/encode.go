package cmd

import (
	"github.com/spf13/cobra"
)

// encodeCmd represents the encode command
var encodeCmd = &cobra.Command{
	Use:   "encode",
	Short: "encode JWT token",
	Long:  `encode JWT token`,
}
