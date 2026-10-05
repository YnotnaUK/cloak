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

// Process encrypts or decrypts files in place. With no paths it walks the whole project.
func Process(decrypt bool, paths []string) error {
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

	if len(paths) > 0 {
		for _, path := range paths {
			rule, err := resolveFile(cfg, path)
			if err != nil {
				return err
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if err := processFile(cfg, filepath.Clean(path), info.Mode().Perm(), rule, decrypt, privKey); err != nil {
				return err
			}
		}
		return nil
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

		info, err := d.Info()
		if err != nil {
			return err
		}
		return processFile(cfg, path, info.Mode().Perm(), rule, decrypt, privKey)
	})
}

func processFile(cfg *config.Config, path string, perm fs.FileMode, rule *config.Rule, decrypt bool, privKey string) error {
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
			return crypto.Encrypt(b, cfg.Keys())
		})
	}
	if err != nil {
		return fmt.Errorf("failed processing %s: %w", path, err)
	}

	if err := os.WriteFile(path, processed, perm); err != nil {
		return fmt.Errorf("failed writing %s: %w", path, err)
	}

	action := "Encrypted"
	if decrypt {
		action = "Decrypted"
	}
	fmt.Printf("%s: %s\n", action, path)
	return nil
}

// resolveFile validates an explicitly requested file against the project config.
func resolveFile(cfg *config.Config, path string) (*config.Rule, error) {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%s is outside the project", path)
	}
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if cfg.IsExcluded(clean) {
		return nil, fmt.Errorf("%s is excluded in %s", path, config.ConfigFileName)
	}
	rule := cfg.FindRule(clean)
	if rule == nil {
		return nil, fmt.Errorf("%s does not match any rule in %s", path, config.ConfigFileName)
	}
	return rule, nil
}

func loadForRead(path string) (*config.Config, formats.Formatter, []byte, string, *config.Rule, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, nil, "", nil, err
	}
	rule, err := resolveFile(cfg, path)
	if err != nil {
		return nil, nil, nil, "", nil, err
	}
	formatter, err := formats.Get(rule.Type)
	if err != nil {
		return nil, nil, nil, "", nil, err
	}
	privKey, err := cryptoPrivateKeyLoader()
	if err != nil {
		return nil, nil, nil, "", nil, err
	}
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, nil, nil, "", nil, fmt.Errorf("failed reading %s: %w", path, err)
	}
	return cfg, formatter, content, privKey, rule, nil
}

// DecryptFile returns the decrypted content of a file without touching disk.
func DecryptFile(path string) ([]byte, error) {
	_, formatter, content, privKey, _, err := loadForRead(path)
	if err != nil {
		return nil, err
	}
	return formatter.Decrypt(content, func(s string) ([]byte, error) {
		return crypto.Decrypt(s, privKey)
	})
}

// ExtractValue returns a single decrypted value from a file without touching disk.
func ExtractValue(path, keyPath string) ([]byte, error) {
	_, formatter, content, privKey, _, err := loadForRead(path)
	if err != nil {
		return nil, err
	}
	return formatter.Extract(content, keyPath, func(s string) ([]byte, error) {
		return crypto.Decrypt(s, privKey)
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
			return crypto.Encrypt(b, cfg.Keys())
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
