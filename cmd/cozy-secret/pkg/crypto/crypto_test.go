package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		plaintext string
		password  string
		wantErr   bool
	}{
		{
			name:      "simple text",
			plaintext: "Hello, World!",
			password:  "password123",
			wantErr:   false,
		},
		{
			name:      "empty text",
			plaintext: "",
			password:  "password123",
			wantErr:   false,
		},
		{
			name:      "empty password",
			plaintext: "test",
			password:  "",
			wantErr:   true,
		},
		{
			name:      "unicode text",
			plaintext: "Hello",
			password:  "password123",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.plaintext, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			decrypted, err := Decrypt(encrypted, tt.password)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}

			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncryptDifferentSalts(t *testing.T) {
	plaintext := "Hello, World!"
	password := "password123"

	// Encrypt the same text twice
	encrypted1, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	encrypted2, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Verify that the encrypted texts are different due to different salts
	if encrypted1 == encrypted2 {
		t.Error("Encrypted texts should be different due to different salts")
	}

	// Verify both can be decrypted correctly
	decrypted1, err := Decrypt(encrypted1, password)
	if err != nil {
		t.Errorf("Decrypt() error = %v", err)
	}
	if decrypted1 != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decrypted1, plaintext)
	}

	decrypted2, err := Decrypt(encrypted2, password)
	if err != nil {
		t.Errorf("Decrypt() error = %v", err)
	}
	if decrypted2 != plaintext {
		t.Errorf("Decrypt() = %v, want %v", decrypted2, plaintext)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	plaintext := "Hello, World!"
	password := "password123"
	wrongPassword := "wrongpassword"

	// Encrypt with correct password
	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt with wrong password
	_, err = Decrypt(encrypted, wrongPassword)
	if err == nil {
		t.Error("Decrypt() with wrong password should return an error")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	tests := []struct {
		name      string
		encrypted string
		password  string
		wantErr   bool
	}{
		{
			name:      "empty string",
			encrypted: "",
			password:  "password123",
			wantErr:   true,
		},
		{
			name:      "invalid base64",
			encrypted: "not-base64-data",
			password:  "password123",
			wantErr:   true,
		},
		{
			name:      "too short",
			encrypted: "aGVsbG8=", // "hello" in base64
			password:  "password123",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.encrypted, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCryptoError(t *testing.T) {
	err := &CryptoError{
		Op:  "test",
		Err: nil,
	}
	
	errorMsg := err.Error()
	if !strings.Contains(errorMsg, "test") {
		t.Errorf("CryptoError.Error() = %v, want to contain 'test'", errorMsg)
	}
}

func TestFileOperations(t *testing.T) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "crypto_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test file
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "test content"
	err = os.WriteFile(testFile, []byte(testContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test encryption
	err = EncryptFile(testFile, "testpass")
	if err != nil {
		t.Errorf("EncryptFile() error = %v", err)
		return
	}

	// Verify file permissions
	info, err := os.Stat(testFile)
	if err != nil {
		t.Errorf("Failed to stat file: %v", err)
		return
	}
	if info.Mode().Perm() != filePerm {
		t.Errorf("File has wrong permissions: got %v, want %v", info.Mode().Perm(), filePerm)
	}

	// Test decryption
	err = DecryptFile(testFile, "testpass")
	if err != nil {
		t.Errorf("DecryptFile() error = %v", err)
		return
	}

	// Verify content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Errorf("Failed to read file: %v", err)
		return
	}
	if string(content) != testContent {
		t.Errorf("Wrong content after decryption: got %v, want %v", string(content), testContent)
	}
}

func TestSecureWipe(t *testing.T) {
	data := []byte("sensitive data")
	original := make([]byte, len(data))
	copy(original, data)

	secureWipe(data)

	// Verify data was wiped
	for i, b := range data {
		if b != 0 {
			t.Errorf("Data not properly wiped at position %d: got %d, want 0", i, b)
		}
	}

	// Verify original data is different
	different := false
	for i := range data {
		if data[i] != original[i] {
			different = true
			break
		}
	}
	if !different {
		t.Error("secureWipe did not modify the data")
	}
}
