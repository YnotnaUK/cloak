package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Generate creates a new X25519 keypair and writes it to disk.
func Generate(force bool) (string, string, error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key: %w", err)
	}
	pubKey := privKey.PublicKey()

	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("failed to get config dir: %w", err)
	}

	cloakDir := filepath.Join(configDir, "cloak")
	if err := os.MkdirAll(cloakDir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create directory: %w", err)
	}

	keyFilePath := filepath.Join(cloakDir, "key.txt")

	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}

	f, err := os.OpenFile(keyFilePath, flags, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", "", fmt.Errorf("key file already exists at %s (use -f or --force to overwrite)", keyFilePath)
		}
		return "", "", fmt.Errorf("failed to create key file: %w", err)
	}
	defer f.Close()

	pubHex := hex.EncodeToString(pubKey.Bytes())
	privHex := hex.EncodeToString(privKey.Bytes())

	content := fmt.Sprintf("# Public Key: %s\n%s\n", pubHex, privHex)
	if _, err := f.WriteString(content); err != nil {
		return "", "", fmt.Errorf("failed to write key: %w", err)
	}

	return pubHex, keyFilePath, nil
}

// ReadPublicKey extracts the public key from the default key file.
func ReadPublicKey() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config dir: %w", err)
	}

	keyFilePath := filepath.Join(configDir, "cloak", "key.txt")
	data, err := os.ReadFile(keyFilePath)
	if err != nil {
		return "", fmt.Errorf("could not read key file (run 'cloak keygen' first): %w", err)
	}

	// Parse the first comment line: "# Public Key: <hex>"
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# Public Key:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# Public Key:")), nil
		}
	}

	return "", errors.New("public key not found in key file")
}

// ReadPrivateKey extracts the private key hex from the key file.
func ReadPrivateKey() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config dir: %w", err)
	}

	keyFilePath := filepath.Join(configDir, "cloak", "key.txt")
	data, err := os.ReadFile(keyFilePath)
	if err != nil {
		return "", fmt.Errorf("could not read key file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line, nil
		}
	}

	return "", errors.New("private key not found in key file")
}
