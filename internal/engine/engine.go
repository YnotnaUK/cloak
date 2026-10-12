package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/ynotnauk/cloak/internal/config"
	"github.com/ynotnauk/cloak/internal/crypto"
	"github.com/ynotnauk/cloak/internal/fileio"
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
		var errs []error
		for _, path := range paths {
			rule, err := resolveFile(cfg, path)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed resolving %s: %w", path, err))
				continue
			}
			info, err := os.Stat(path)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed reading file information for %s: %w", path, err))
				continue
			}
			if err := processFile(cfg, filepath.Clean(path), info.Mode().Perm(), rule, decrypt, privKey); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}

	var errs []error
	walkErr := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Errorf("failed walking %s: %w", path, err))
			return nil
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

		rule, err := cfg.FindRule(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed matching rule for %s: %w", path, err))
			return nil
		}
		if rule == nil {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed reading file information for %s: %w", path, err))
			return nil
		}
		if err := processFile(cfg, path, info.Mode().Perm(), rule, decrypt, privKey); err != nil {
			errs = append(errs, err)
		}
		return nil
	})
	if walkErr != nil {
		errs = append(errs, fmt.Errorf("failed walking project: %w", walkErr))
	}
	return errors.Join(errs...)
}

func processFile(cfg *config.Config, path string, perm fs.FileMode, rule *config.Rule, decrypt bool, privKey string) error {
	formatter, err := formats.Get(rule.Type)
	if err != nil {
		return fmt.Errorf("failed processing %s: %w", path, err)
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

	if bytes.Equal(content, processed) {
		return nil
	}

	if err := fileio.WriteFile(path, processed, perm); err != nil {
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
	rule, err := cfg.FindRule(clean)
	if err != nil {
		return nil, err
	}
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

func Rekey() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	return rekey(cfg, false)
}

// RekeyWithConfig rekeys all encrypted files for cfg and saves cfg only after
// every file has been re-encrypted successfully.
func RekeyWithConfig(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid %s: %w", config.ConfigFileName, err)
	}
	return rekey(cfg, true)
}

type rekeyedFile struct {
	path      string
	writePath string
	original  []byte
	rekeyed   []byte
	mode      fs.FileMode
}

func rekey(cfg *config.Config, saveConfig bool) error {
	privKey, err := cryptoPrivateKeyLoader()
	if err != nil {
		return err
	}

	var files []rekeyedFile
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
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

		rule, err := cfg.FindRule(path)
		if err != nil {
			return err
		}
		if rule == nil {
			return nil
		}

		formatter, err := formats.Get(rule.Type)
		if err != nil {
			return fmt.Errorf("failed rekeying %s: %w", path, err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed reading %s: %w", path, err)
		}

		// Skip files that are not encrypted
		if !strings.Contains(string(content), crypto.Prefix) {
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
		writePath := path
		if info.Mode()&os.ModeSymlink != 0 {
			writePath, err = filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("failed resolving %s for rekey: %w", path, err)
			}
			info, err = os.Stat(writePath)
			if err != nil {
				return fmt.Errorf("failed reading file info for %s: %w", path, err)
			}
		}
		files = append(files, rekeyedFile{
			path:      path,
			writePath: writePath,
			original:  content,
			rekeyed:   rekeyed,
			mode:      info.Mode().Perm(),
		})
		return nil
	})
	if err != nil {
		return err
	}

	committed := 0
	for _, file := range files {
		if err := fileio.WriteFile(file.writePath, file.rekeyed, file.mode); err != nil {
			writeErr := fmt.Errorf("failed writing %s: %w", file.path, err)
			return errors.Join(writeErr, rollbackRekeyedFiles(files, committed))
		}
		committed++
	}

	if saveConfig {
		if err := cfg.Save(); err != nil {
			saveErr := fmt.Errorf("failed saving %s after rekey: %w", config.ConfigFileName, err)
			return errors.Join(saveErr, rollbackRekeyedFiles(files, committed))
		}
	}

	for _, file := range files {
		fmt.Printf("Rekeyed: %s\n", file.path)
	}
	return nil
}

func rollbackRekeyedFiles(files []rekeyedFile, committed int) error {
	var rollbackErr error
	for i := committed - 1; i >= 0; i-- {
		file := files[i]
		if err := fileio.WriteFile(file.writePath, file.original, file.mode); err != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("failed restoring %s: %w", file.path, err))
		}
	}
	return rollbackErr
}
