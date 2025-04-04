package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize   = 32
	nonceSize  = 12
	keySize    = 32
	iterations = 310000
	filePerm   = 0600  // Only owner can read/write
)

// CryptoError represents a cryptographic operation error
type CryptoError struct {
	Op  string
	Err error
}

func (e *CryptoError) Error() string {
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

// deriveKey generates a cryptographic key from a password using PBKDF2 with memory-hard function
func deriveKey(password string, salt []byte) []byte {
	// Use Argon2id for memory-hard key derivation
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, keySize)
}

// secureWipe overwrites a byte slice with random data and then zeros
func secureWipe(data []byte) {
	// First overwrite with random data
	if _, err := rand.Read(data); err != nil {
		// If random generation fails, at least overwrite with a pattern
		for i := range data {
			data[i] = byte(i % 256)
		}
	}
	// Then zero out
	for i := range data {
		data[i] = 0
	}
}

// Encrypt encrypts data using a password
func Encrypt(plaintext, password string) (string, error) {
	// Check for empty password
	if password == "" {
		return "", &CryptoError{Op: "encrypt", Err: fmt.Errorf("password cannot be empty")}
	}

	// Generate random salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", &CryptoError{Op: "generate salt", Err: err}
	}
	defer secureWipe(salt)

	// Derive key from password
	key := deriveKey(password, salt)
	defer secureWipe(key)

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", &CryptoError{Op: "create cipher", Err: err}
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &CryptoError{Op: "create GCM", Err: err}
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", &CryptoError{Op: "generate nonce", Err: err}
	}
	defer secureWipe(nonce)

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// Combine salt and ciphertext
	combined := make([]byte, len(salt)+len(ciphertext))
	copy(combined, salt)
	copy(combined[len(salt):], ciphertext)

	return base64.StdEncoding.EncodeToString(combined), nil
}

// EncryptVaultStyle encrypts data using a password and formats it like Ansible Vault
func EncryptVaultStyle(plaintext, password string) (string, error) {
	// Encrypt the data
	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		return "", err
	}

	// Format like Ansible Vault
	// $ANSIBLE_VAULT;1.1;AES256
	// [encrypted data in hex format, 80 chars per line]
	
	// Convert base64 to hex
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", &CryptoError{Op: "decode base64", Err: err}
	}
	
	// Convert to hex
	hexData := fmt.Sprintf("%x", decoded)
	
	// Split into 80-character lines
	var lines []string
	for i := 0; i < len(hexData); i += 80 {
		end := i + 80
		if end > len(hexData) {
			end = len(hexData)
		}
		lines = append(lines, hexData[i:end])
	}
	
	// Format as Ansible Vault
	result := "$GO_VAULT;1.1;AES256\n"
	result += strings.Join(lines, "\n")
	
	return result, nil
}

// Decrypt decrypts data using a password
func Decrypt(encrypted, password string) (string, error) {
	// Check for empty password
	if password == "" {
		return "", &CryptoError{Op: "decrypt", Err: fmt.Errorf("password cannot be empty")}
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", &CryptoError{Op: "decode base64", Err: err}
	}
	defer secureWipe(data)

	if len(data) < saltSize {
		return "", &CryptoError{Op: "decrypt", Err: fmt.Errorf("encrypted data too short")}
	}

	// Extract salt and ciphertext
	salt := data[:saltSize]
	ciphertext := data[saltSize:]

	// Derive key from password
	key := deriveKey(password, salt)
	defer secureWipe(key)

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", &CryptoError{Op: "create cipher", Err: err}
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &CryptoError{Op: "create GCM", Err: err}
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", &CryptoError{Op: "decrypt", Err: fmt.Errorf("ciphertext too short")}
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	defer secureWipe(nonce)

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", &CryptoError{Op: "decrypt", Err: err}
	}
	defer secureWipe(plaintext)

	return string(plaintext), nil
}

// DecryptVaultStyle decrypts data in Ansible Vault format using a password
func DecryptVaultStyle(encrypted, password string) (string, error) {
	// Check if it's in Ansible Vault format or Go Vault format
	if !strings.HasPrefix(encrypted, "$ANSIBLE_VAULT;") && !strings.HasPrefix(encrypted, "$GO_VAULT;") {
		return "", &CryptoError{Op: "decrypt", Err: fmt.Errorf("not in Vault format (expected $ANSIBLE_VAULT; or $GO_VAULT; prefix)")}
	}
	
	// Split into lines
	lines := strings.Split(encrypted, "\n")
	if len(lines) < 2 {
		return "", &CryptoError{Op: "decrypt", Err: fmt.Errorf("invalid Vault format")}
	}
	
	// Skip the header line
	hexData := strings.Join(lines[1:], "")
	
	// Convert hex to bytes
	data := make([]byte, len(hexData)/2)
	for i := 0; i < len(hexData); i += 2 {
		var val byte
		fmt.Sscanf(hexData[i:i+2], "%02x", &val)
		data[i/2] = val
	}
	
	// Convert to base64
	base64Data := base64.StdEncoding.EncodeToString(data)
	
	// Decrypt
	return Decrypt(base64Data, password)
}

// checkFilePermissions checks if a file has secure permissions
func checkFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	
	mode := info.Mode()
	if mode&0077 != 0 { // Check if others or group have any permissions
		return fmt.Errorf("file %s has insecure permissions: %v", path, mode)
	}
	return nil
}

// EncryptFile encrypts a file in-place using a password
func EncryptFile(filename, password string) error {
	// Check file permissions
	if err := checkFilePermissions(filename); err != nil {
		return &CryptoError{Op: "check permissions", Err: err}
	}

	// Read file contents
	content, err := os.ReadFile(filename)
	if err != nil {
		return &CryptoError{Op: "read file", Err: err}
	}
	defer secureWipe(content)

	// Encrypt the content
	encrypted, err := Encrypt(string(content), password)
	if err != nil {
		return err
	}

	// Write encrypted content back to the same file with secure permissions
	if err := os.WriteFile(filename, []byte(encrypted), filePerm); err != nil {
		return &CryptoError{Op: "write file", Err: err}
	}

	return nil
}

// EncryptFileVaultStyle encrypts a file in-place using a password in Ansible Vault format
func EncryptFileVaultStyle(filename, password string) error {
	// Read file contents
	content, err := os.ReadFile(filename)
	if err != nil {
		return &CryptoError{Op: "read file", Err: err}
	}

	// Encrypt the content in Vault style
	encrypted, err := EncryptVaultStyle(string(content), password)
	if err != nil {
		return err
	}

	// Write encrypted content back to the same file
	if err := os.WriteFile(filename, []byte(encrypted), 0600); err != nil {
		return &CryptoError{Op: "write file", Err: err}
	}

	return nil
}

// DecryptFile decrypts a file in-place using a password
func DecryptFile(filename, password string) error {
	// Check file permissions
	if err := checkFilePermissions(filename); err != nil {
		return &CryptoError{Op: "check permissions", Err: err}
	}

	// Read encrypted file contents
	content, err := os.ReadFile(filename)
	if err != nil {
		return &CryptoError{Op: "read file", Err: err}
	}
	defer secureWipe(content)

	// Decrypt the content
	decrypted, err := Decrypt(string(content), password)
	if err != nil {
		return err
	}

	// Write decrypted content back to the same file with secure permissions
	if err := os.WriteFile(filename, []byte(decrypted), filePerm); err != nil {
		return &CryptoError{Op: "write file", Err: err}
	}

	return nil
}

// DecryptFileVaultStyle decrypts a file in-place using a password, assuming Ansible Vault format
func DecryptFileVaultStyle(filename, password string) error {
	// Read encrypted file contents
	content, err := os.ReadFile(filename)
	if err != nil {
		return &CryptoError{Op: "read file", Err: err}
	}

	// Decrypt the content
	decrypted, err := DecryptVaultStyle(string(content), password)
	if err != nil {
		return err
	}

	// Write decrypted content back to the same file
	if err := os.WriteFile(filename, []byte(decrypted), 0600); err != nil {
		return &CryptoError{Op: "write file", Err: err}
	}

	return nil
} 