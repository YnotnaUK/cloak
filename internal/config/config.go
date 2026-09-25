package config

import (
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
