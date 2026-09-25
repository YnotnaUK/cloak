package config

import (
	"errors"
	"fmt"
	"os"

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
