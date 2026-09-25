package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

const ConfigFileName = ".cloak.yaml"

type Rule struct {
	PathRegex     string   `yaml:"path_regex"`
	Type          string   `yaml:"type"` // "full", "yaml", "json", "env"
	EncryptedKeys []string `yaml:"encrypted_keys,omitempty"`
}

type Config struct {
	Recipients []string `yaml:"recipients"`
	Rules      []Rule   `yaml:"rules"`
}

func Init(pubKey string, force bool) error {
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
		Recipients: []string{pubKey},
		Rules: []Rule{
			{
				PathRegex: `.*\.secret$`,
				Type:      "full",
			},
			{
				PathRegex:     `.*\.ya?ml$`,
				Type:          "yaml",
				EncryptedKeys: []string{"password", "secret", "token"},
			},
			{
				PathRegex:     `.*\.json$`,
				Type:          "json",
				EncryptedKeys: []string{"password", "secret", "token"},
			},
			{
				PathRegex:     `.*\.env$`,
				Type:          "env",
				EncryptedKeys: []string{"PASSWORD", "SECRET_KEY"},
			},
		},
	}

	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	return encoder.Encode(cfg)
}

// Load reads and parses .cloak.yaml from the current directory.
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

// FindRule matches a file path against configured rules in order.
func (c *Config) FindRule(path string) (*Rule, error) {
	for _, rule := range c.Rules {
		matched, err := regexp.MatchString(rule.PathRegex, path)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", rule.PathRegex, err)
		}
		if matched {
			return &rule, nil
		}
	}
	return nil, fmt.Errorf("no rule found matching path %q", path)
}
