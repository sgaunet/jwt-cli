package cmd

import (
	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command.
var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "decode JWT token",
	Long:  `decode JWT token`,
}
