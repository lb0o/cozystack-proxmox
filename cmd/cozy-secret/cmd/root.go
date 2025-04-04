package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "cozy-secret",
	Short: "A secure file encryption and decryption tool",
	Long: `cozy-secret is a CLI tool for secure file encryption and decryption.
It uses AES-GCM encryption with PBKDF2 key derivation for secure password-based encryption.

Example usage:
  cozy-secret encrypt file.txt -p mypassword
  cozy-secret decrypt file.txt.enc -p mypassword`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
} 