package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"cozy-secret/pkg/crypto"
)

var (
	password     string
	passwordFile string
	vaultStyle   bool
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt a file",
	Long: `Encrypt a file using password-based encryption.
The file will be encrypted in-place.

Examples:
  # Encrypt using password directly
  cozy-secret encrypt myfile.txt -p mypassword

  # Encrypt using password from a file
  cozy-secret encrypt myfile.txt -f password.txt
  
  # Encrypt in Vault style format (Ansible Vault or Go Vault)
  cozy-secret encrypt myfile.txt -p mypassword -v`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return encryptFile(args[0])
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringVarP(&password, "password", "p", "", "encryption password")
	encryptCmd.Flags().StringVarP(&passwordFile, "password-file", "f", "", "file containing the encryption password")
	encryptCmd.Flags().BoolVarP(&vaultStyle, "vault", "v", false, "use Vault style output format (Ansible Vault or Go Vault)")
	encryptCmd.MarkFlagsMutuallyExclusive("password", "password-file")
}

func getPassword() (string, error) {
	if password != "" {
		return password, nil
	}
	if passwordFile != "" {
		content, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("reading password file: %v", err)
		}
		return string(content), nil
	}
	return "", fmt.Errorf("either --password or --password-file must be provided")
}

func encryptFile(filename string) error {
	// Get password
	masterPassword, err := getPassword()
	if err != nil {
		return err
	}

	// Encrypt file in-place
	if vaultStyle {
		if err := crypto.EncryptFileVaultStyle(filename, masterPassword); err != nil {
			return fmt.Errorf("encrypting file: %v", err)
		}
		fmt.Printf("File encrypted successfully in Vault format: %s\n", filename)
	} else {
		if err := crypto.EncryptFile(filename, masterPassword); err != nil {
			return fmt.Errorf("encrypting file: %v", err)
		}
		fmt.Printf("File encrypted successfully: %s\n", filename)
	}
	
	return nil
} 