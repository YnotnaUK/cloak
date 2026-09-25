package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const ConfigFileName = ".cloak.yaml"

type Rule struct {
	PathRegex     string   `yaml:"path_regex"`
	Type          string   `yaml:"type"`
	EncryptedKeys []string `yaml:"encrypted_keys,omitempty"`
}

type Config struct {
	Recipients []string `yaml:"recipients"`
	Exclude    []string `yaml:"exclude"`
	Rules      []Rule   `yaml:"rules"`
}

// Replace the signature and assignment in Init:
func Init(recipients []string, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}

	f, err := os.OpenFile(ConfigFileName, flags, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists (use -f to overwrite)", ConfigFileName)
		}
		return err
	}
	defer f.Close()

	cfg := Config{
		Recipients: recipients,
		Exclude: []string{
			".git",
			"node_modules",
			"bin",
			"coverage",
			ConfigFileName,
		},
		Rules: []Rule{
			{PathRegex: `.*\.secret$`, Type: "full"},
			{PathRegex: `.*\.ya?ml$`, Type: "yaml", EncryptedKeys: []string{"password", "secret", "token"}},
			{PathRegex: `.*\.json$`, Type: "json", EncryptedKeys: []string{"password", "secret", "token"}},
			{PathRegex: `.*\.env$`, Type: "env", EncryptedKeys: []string{"PASSWORD", "SECRET_KEY"}},
		},
	}

	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	return encoder.Encode(cfg)
}

func Load() (*Config, error) {
	data, err := os.ReadFile(ConfigFileName)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", ConfigFileName, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", ConfigFileName, err)
	}

	return &cfg, nil
}

func (c *Config) IsExcluded(path string) bool {
	cleanPath := filepath.Clean(path)
	parts := strings.Split(cleanPath, string(filepath.Separator))
	for _, part := range parts {
		for _, exc := range c.Exclude {
			if part == exc {
				return true
			}
		}
	}
	return false
}

func (c *Config) FindRule(path string) *Rule {
	for _, rule := range c.Rules {
		matched, _ := regexp.MatchString(rule.PathRegex, path)
		if matched {
			return &rule
		}
	}
	return nil
}

// Save writes the updated config back to .cloak.yaml
func (c *Config) Save() error {
	f, err := os.OpenFile(ConfigFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	return encoder.Encode(c)
}

// AddRecipient cryptographically validates the public key before adding it.
func (c *Config) AddRecipient(key string) error {
	key = strings.TrimSpace(key)
	if len(key) != 64 {
		return fmt.Errorf("invalid recipient public key length (expected 64 hex characters)")
	}

	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("invalid hex encoding: %w", err)
	}

	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(keyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Test ECDH against a temporary key to detect low-order points upfront
	dummyPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("crypto error: %w", err)
	}
	if _, err := dummyPriv.ECDH(pub); err != nil {
		return fmt.Errorf("invalid X25519 public key: %w", err)
	}

	for _, r := range c.Recipients {
		if r == key {
			return fmt.Errorf("recipient already exists")
		}
	}

	c.Recipients = append(c.Recipients, key)
	return c.Save()
}

// RemoveRecipient removes a key from the recipient list.
func (c *Config) RemoveRecipient(key string) error {
	key = strings.TrimSpace(key)
	found := false
	var updated []string

	for _, r := range c.Recipients {
		if r == key {
			found = true
			continue
		}
		updated = append(updated, r)
	}

	if !found {
		return fmt.Errorf("recipient %s not found in %s", key, ConfigFileName)
	}

	if len(updated) == 0 {
		return fmt.Errorf("cannot remove last recipient; at least one recipient is required")
	}

	c.Recipients = updated
	return c.Save()
}
