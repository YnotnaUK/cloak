package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "keygen" {
		fmt.Println("Usage: cloak keygen")
		os.Exit(1)
	}

	if err := runKeygen(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runKeygen() error {
	// 1. Generate an X25519 private key
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	pubKey := privKey.PublicKey()

	// 2. Resolve XDG config directory
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config dir: %w", err)
	}
	cloakDir := filepath.Join(configDir, "cloak")

	// Ensure directory exists with 0700 permissions (user-only)
	if err := os.MkdirAll(cloakDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	keyFilePath := filepath.Join(cloakDir, "key.txt")

	// 3. Format key contents
	content := fmt.Sprintf("# Public Key: %s\n%s\n",
		hex.EncodeToString(pubKey.Bytes()),
		hex.EncodeToString(privKey.Bytes()),
	)

	// 4. Write key file with 0600 permissions (read/write by user only)
	if err := os.WriteFile(keyFilePath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	fmt.Printf("Key generated successfully!\n")
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(pubKey.Bytes()))
	fmt.Printf("Saved to:   %s\n", keyFilePath)

	return nil
}
