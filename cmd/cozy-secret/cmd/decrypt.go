package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"cozy-secret/pkg/crypto"
)

var (
	decryptPassword     string
	decryptPasswordFile string
	decryptVaultStyle   bool
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt a file",
	Long: `Decrypt a file using password-based encryption.
The file will be decrypted in-place.

Examples:
  # Decrypt using password directly
  cozy-secret decrypt myfile.txt -p mypassword

  # Decrypt using password from a file
  cozy-secret decrypt myfile.txt -f password.txt
  
  # Decrypt Vault style file (Ansible Vault or Go Vault format)
  cozy-secret decrypt myfile.txt -p mypassword -v`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate file exists
		if _, err := os.Stat(args[0]); os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", args[0])
		}

		return decryptFile(args[0])
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringVarP(&decryptPassword, "password", "p", "", "decryption password")
	decryptCmd.Flags().StringVarP(&decryptPasswordFile, "password-file", "f", "", "file containing the decryption password")
	decryptCmd.Flags().BoolVarP(&decryptVaultStyle, "vault", "v", false, "use Vault style input format (Ansible Vault or Go Vault)")
	decryptCmd.MarkFlagsMutuallyExclusive("password", "password-file")
	
	// At least one of password or password-file must be provided
	decryptCmd.MarkFlagsOneRequired("password", "password-file")
}

func getDecryptPassword() (string, error) {
	if decryptPassword != "" {
		return decryptPassword, nil
	}
	if decryptPasswordFile != "" {
		content, err := os.ReadFile(decryptPasswordFile)
		if err != nil {
			return "", fmt.Errorf("reading password file: %v", err)
		}
		return string(content), nil
	}
	return "", fmt.Errorf("either --password or --password-file must be provided")
}

func decryptFile(filename string) error {
	// Get password
	masterPassword, err := getDecryptPassword()
	if err != nil {
		return err
	}

	// Check if file is in Ansible Vault format
	if decryptVaultStyle {
		// Decrypt file in-place using Vault style
		if err := crypto.DecryptFileVaultStyle(filename, masterPassword); err != nil {
			return fmt.Errorf("decrypting file: %v", err)
		}
		fmt.Printf("File decrypted successfully from Vault format: %s\n", filename)
	} else {
		// Check if file is in Ansible Vault format anyway
		content, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("reading file: %v", err)
		}
		
		if strings.HasPrefix(string(content), "$GO_VAULT;") || strings.HasPrefix(string(content), "$ANSIBLE_VAULT;") {
			fmt.Println("Warning: File appears to be in Vault format. Use --vault flag for proper decryption.")
		}
		
		// Decrypt file in-place
		if err := crypto.DecryptFile(filename, masterPassword); err != nil {
			return fmt.Errorf("decrypting file: %v", err)
		}
		fmt.Printf("File decrypted successfully: %s\n", filename)
	}
	
	return nil
} 