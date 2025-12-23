package cmd

import (
	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command.
var decodeCmd = &cobra.Command{
	Use:       "decode",
	Short:     "decode JWT token",
	Long:      `decode JWT token`,
	ValidArgs: []string{"hs256", "hs384", "hs512", "rs256", "rs384", "rs512", "es256", "es384", "es512"},
}
