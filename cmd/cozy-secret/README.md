# cozy-secret

A lightweight command-line tool for secure file encryption and decryption, inspired by ansible-vault.

## Overview

`cozy-secret` provides a simple way to encrypt and decrypt files with password protection. While not as feature-rich as ansible-vault, it offers a convenient solution for basic file encryption without requiring a full Ansible installation.

> **Note**: This tool is designed for basic file encryption needs. For production use cases requiring high security, consider using more robust solutions like ansible-vault or GPG.

## Installation

### From Source
```bash
git clone <repository-url>
cd cozy-secret
go build
```

### Using Go
```bash
go install cozy-secret@latest
```

## Usage

### Basic Syntax
```bash
cozy-secret [OPTIONS] COMMAND [ARGS]
```

### Options

| Option | Description |
|--------|-------------|
| `-p, --password PASSWORD` | Use specified password for encryption/decryption |
| `-f, --password-file FILE` | Read password from specified file |
| `-v, --vault` | Use Ansible Vault style format |

### Commands

| Command | Description |
|---------|-------------|
| `encrypt FILE` | Encrypt the specified file |
| `decrypt FILE` | Decrypt the specified file |

### Examples

#### Encrypting Files
```bash
# Using a password
cozy-secret encrypt file.txt -p mypassword

# Using a password file
cozy-secret encrypt file.txt -f password.txt

# Using Ansible Vault format
cozy-secret encrypt file.txt -p mypassword -v
```

#### Decrypting Files
```bash
# Using a password
cozy-secret decrypt file.txt.enc -p mypassword

# Using a password file
cozy-secret decrypt file.txt.enc -f password.txt

# Using Ansible Vault format
cozy-secret decrypt file.txt -p mypassword -v
```

## Security Features

- **Encryption**: Uses AES-GCM for authenticated encryption
- **Key Derivation**: Implements PBKDF2 for secure key derivation
- **Randomization**: Generates random salt and nonce
- **File Permissions**: Sets secure file permissions (0600) for encrypted files

## Related Tools

- [openssl](https://www.openssl.org/)
- [gpg](https://www.gnupg.org/)
- [ansible-vault](https://docs.ansible.com/ansible/latest/cli/ansible-vault.html)

## License
Apache 2.0