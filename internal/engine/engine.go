package engine

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ynotnauk/cloak/internal/config"
	"github.com/ynotnauk/cloak/internal/crypto"
	"github.com/ynotnauk/cloak/internal/formats"
)

var cryptoPrivateKeyLoader func() (string, error)

func SetKeyLoader(loader func() (string, error)) {
	cryptoPrivateKeyLoader = loader
}

func Process(decrypt bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	var privKey string
	if decrypt {
		privKey, err = cryptoPrivateKeyLoader()
		if err != nil {
			return err
		}
	}

	return filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if cfg.IsExcluded(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		rule := cfg.FindRule(path)
		if rule == nil {
			return nil
		}

		formatter, err := formats.Get(rule.Type)
		if err != nil {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed reading %s: %w", path, err)
		}

		var processed []byte
		if decrypt {
			processed, err = formatter.Decrypt(content, func(s string) ([]byte, error) {
				return crypto.Decrypt(s, privKey)
			})
		} else {
			processed, err = formatter.Encrypt(content, rule.EncryptedKeys, func(b []byte) (string, error) {
				return crypto.Encrypt(b, cfg.Recipients)
			})
		}

		if err != nil {
			return fmt.Errorf("failed processing %s: %w", path, err)
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if err := os.WriteFile(path, processed, info.Mode().Perm()); err != nil {
			return fmt.Errorf("failed writing %s: %w", path, err)
		}

		action := "Encrypted"
		if decrypt {
			action = "Decrypted"
		}
		fmt.Printf("%s: %s\n", action, path)
		return nil
	})
}

// In internal/engine/engine.go:
func Rekey() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	privKey, err := cryptoPrivateKeyLoader()
	if err != nil {
		return err
	}

	return filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if cfg.IsExcluded(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		rule := cfg.FindRule(path)
		if rule == nil {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed reading %s: %w", path, err)
		}

		// Skip files that are not encrypted
		if !strings.Contains(string(content), crypto.Prefix) {
			return nil
		}

		formatter, err := formats.Get(rule.Type)
		if err != nil {
			return nil
		}

		// 1. Decrypt in-memory
		decrypted, err := formatter.Decrypt(content, func(s string) ([]byte, error) {
			return crypto.Decrypt(s, privKey)
		})
		if err != nil {
			return fmt.Errorf("failed decrypting %s for rekey: %w", path, err)
		}

		// 2. Re-encrypt with brand new DEK for updated recipients
		rekeyed, err := formatter.Encrypt(decrypted, rule.EncryptedKeys, func(b []byte) (string, error) {
			return crypto.Encrypt(b, cfg.Recipients)
		})
		if err != nil {
			return fmt.Errorf("failed re-encrypting %s: %w", path, err)
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if err := os.WriteFile(path, rekeyed, info.Mode().Perm()); err != nil {
			return fmt.Errorf("failed writing %s: %w", path, err)
		}

		fmt.Printf("Rekeyed: %s\n", path)
		return nil
	})
}
