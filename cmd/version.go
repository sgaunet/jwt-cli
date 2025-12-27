package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	version   = "development"
	commit    = "none"
	buildDate = "unknown"
)

const shortHashLength = 8

// VersionInfo holds detailed version and build information.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
	Compiler  string `json:"compiler"`
}

// getVersionInfo returns detailed version and build information.
func getVersionInfo() VersionInfo {
	info := VersionInfo{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Compiler:  runtime.Compiler,
	}

	// Try to get build info from runtime (useful for local development)
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}

	for _, setting := range bi.Settings {
		if setting.Key == "vcs.revision" && info.Commit == "none" {
			// Use short hash (first 8 chars)
			if len(setting.Value) >= shortHashLength {
				info.Commit = setting.Value[:shortHashLength]
			} else {
				info.Commit = setting.Value
			}
		}
		if setting.Key == "vcs.time" && info.BuildDate == "unknown" {
			info.BuildDate = setting.Value
		}
	}

	return info
}

// versionCmd represents the version command.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long: `Print detailed version and build information for jwt-cli.

Use --json flag for machine-readable output.
Use --short flag for compact output (version only).`,
	Run: func(cmd *cobra.Command, _ []string) {
		info := getVersionInfo()

		jsonOutput, _ := cmd.Flags().GetBool("json")
		shortOutput, _ := cmd.Flags().GetBool("short")

		if shortOutput {
			fmt.Println(info.Version)
			return
		}

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(info); err != nil {
				fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			}
			return
		}

		// Default format
		fmt.Printf("jwt-cli version: %s\n", info.Version)
		fmt.Printf("Git commit: %s\n", info.Commit)
		fmt.Printf("Build date: %s\n", info.BuildDate)
		fmt.Printf("Go version: %s\n", info.GoVersion)
		fmt.Printf("Platform: %s\n", info.Platform)
		fmt.Printf("Compiler: %s\n", info.Compiler)
	},
}

func init() {
	versionCmd.Flags().BoolP("json", "j", false, "output in JSON format")
	versionCmd.Flags().BoolP("short", "s", false, "output version only")
	rootCmd.AddCommand(versionCmd)
}
