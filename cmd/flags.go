package cmd

import (
	"github.com/spf13/cobra"
)

// flagWithFallback reads a flag, falling back to its deprecated short alias.
func flagWithFallback(cmd *cobra.Command, name, deprecated string) string {
	value, _ := cmd.Flags().GetString(name)
	if value == "" {
		value, _ = cmd.Flags().GetString(deprecated) // Check deprecated flag
	}
	return value
}
