package cmd

import (
	"github.com/spf13/cobra"
)

// encodeCmd represents the encode command.
var encodeCmd = &cobra.Command{
	Use:       "encode",
	Short:     "encode JWT token",
	Long:      `encode JWT token`,
	ValidArgs: []string{"hs256", "hs384", "hs512", "rs256", "rs384", "rs512", "es256", "es384", "es512"},
}
