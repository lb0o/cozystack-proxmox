package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Version is the current version of cozy-secret
	Version = "0.1.0"
	// BuildDate is the date the binary was built
	BuildDate = "2025-04-04"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of cozy-secret",
	Long:  `Display the version information for cozy-secret, including version number, build date, and git commit.`,
	Aliases: []string{"v"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("cozy-secret version %s\n", Version)
		fmt.Printf("Build date: %s\n", BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
} 