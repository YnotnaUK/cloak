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

const (
	KindUser       = "user"
	KindCI         = "ci"
	KindBreakGlass = "breakglass"
)

// Recipient is a named public key that can decrypt project files.
type Recipient struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
	Kind string `yaml:"kind,omitempty"`
}

type Config struct {
	Recipients []Recipient `yaml:"recipients"`
	Exclude    []string    `yaml:"exclude"`
	Rules      []Rule      `yaml:"rules"`
}

// Keys returns the public keys of all recipients.
func (c *Config) Keys() []string {
	keys := make([]string, len(c.Recipients))
	for i, r := range c.Recipients {
		keys[i] = r.Key
	}
	return keys
}

func validateKind(kind string) error {
	switch kind {
	case KindUser, KindCI, KindBreakGlass:
		return nil
	}
	return fmt.Errorf("invalid kind %q (expected %s, %s or %s)", kind, KindUser, KindCI, KindBreakGlass)
}

func validatePublicKey(key string) error {
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
	return nil
}

// Validate checks recipient names, kinds, keys and uniqueness.
func (c *Config) Validate() error {
	if len(c.Recipients) == 0 {
		return errors.New("at least one recipient is required")
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	for i := range c.Recipients {
		r := &c.Recipients[i]
		if r.Name == "" {
			return fmt.Errorf("recipient %d: name is required", i+1)
		}
		if r.Kind == "" {
			r.Kind = KindUser
		}
		if err := validateKind(r.Kind); err != nil {
			return fmt.Errorf("recipient %q: %w", r.Name, err)
		}
		if err := validatePublicKey(r.Key); err != nil {
			return fmt.Errorf("recipient %q: %w", r.Name, err)
		}
		if names[r.Name] {
			return fmt.Errorf("duplicate recipient name %q", r.Name)
		}
		if keys[r.Key] {
			return fmt.Errorf("recipient %q: duplicate public key", r.Name)
		}
		names[r.Name], keys[r.Key] = true, true
	}
	return nil
}

func Init(recipients []Recipient, force bool) (err error) {
	for i := range recipients {
		if recipients[i].Kind == "" {
			recipients[i].Kind = KindUser
		}
	}
	if err := (&Config{Recipients: recipients}).Validate(); err != nil {
		return err
	}

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
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

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
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid %s: %w", ConfigFileName, err)
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
func (c *Config) Save() (err error) {
	f, err := os.OpenFile(ConfigFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()

	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	return encoder.Encode(c)
}

// AddRecipient validates and adds a named recipient, then saves the config.
func (c *Config) AddRecipient(name, key, kind string) error {
	r := Recipient{Name: strings.TrimSpace(name), Key: strings.TrimSpace(key), Kind: kind}
	if r.Kind == "" {
		r.Kind = KindUser
	}

	candidate := Config{Recipients: append(append([]Recipient{}, c.Recipients...), r)}
	if err := candidate.Validate(); err != nil {
		return err
	}

	c.Recipients = candidate.Recipients
	return c.Save()
}

// RemoveRecipient removes a recipient by name or public key.
func (c *Config) RemoveRecipient(nameOrKey string) (*Recipient, error) {
	nameOrKey = strings.TrimSpace(nameOrKey)
	var removed *Recipient
	var updated []Recipient

	for _, r := range c.Recipients {
		if removed == nil && (r.Name == nameOrKey || r.Key == nameOrKey) {
			r := r
			removed = &r
			continue
		}
		updated = append(updated, r)
	}

	if removed == nil {
		return nil, fmt.Errorf("recipient %q not found in %s", nameOrKey, ConfigFileName)
	}
	if len(updated) == 0 {
		return nil, fmt.Errorf("cannot remove last recipient; at least one recipient is required")
	}

	c.Recipients = updated
	return removed, c.Save()
}
