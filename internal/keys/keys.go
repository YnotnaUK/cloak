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
