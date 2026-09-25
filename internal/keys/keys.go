package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Generate creates a new X25519 keypair and writes it to disk.
// Returns an error if the key file already exists.
func Generate() (string, string, error) {
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

	// os.O_EXCL causes OpenFile to fail if the file already exists
	f, err := os.OpenFile(keyFilePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", "", fmt.Errorf("key file already exists at %s (use a force flag or remove it manually)", keyFilePath)
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
