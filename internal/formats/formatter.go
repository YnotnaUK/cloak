package formats

import (
	"fmt"
)

type Formatter interface {
	Encrypt(content []byte, keys []string, encryptFn func([]byte) (string, error)) ([]byte, error)
	Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error)
}

func Get(formatType string) (Formatter, error) {
	switch formatType {
	case "full":
		return &FullFormatter{}, nil
	case "env":
		return &EnvFormatter{}, nil
	case "json":
		return &JsonFormatter{}, nil
	case "yaml":
		return &YamlFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported format type: %s", formatType)
	}
}
