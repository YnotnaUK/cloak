package identity

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/YnotnaUK/cloak/internal/crypto"
)

func SaveKeyPair(kp *crypto.KeyPair, force bool) (privPath string, pubPath string, err error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", "", fmt.Errorf("could not find user config dir: %w", err)
	}

	cloakDir := filepath.Join(configDir, "cloak")
	privPath = filepath.Join(cloakDir, "key")
	pubPath = filepath.Join(cloakDir, "key.pub")

	// Guard against overwrites
	if !force {
		if _, err := os.Stat(privPath); err == nil {
			return "", "", fmt.Errorf("keys already exist at %s\nUse --force to overwrite", privPath)
		}
	}

	// Create ~/.config/cloak with 0700
	if err := os.MkdirAll(cloakDir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create directory %s: %w", cloakDir, err)
	}

	// Write private key with 0600
	if err := os.WriteFile(privPath, []byte(kp.Private+"\n"), 0600); err != nil {
		return "", "", fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key with 0644
	if err := os.WriteFile(pubPath, []byte(kp.Public+"\n"), 0644); err != nil {
		return "", "", fmt.Errorf("failed to write public key: %w", err)
	}

	return privPath, pubPath, nil
}
