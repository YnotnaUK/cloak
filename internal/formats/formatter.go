package formats

import (
	"fmt"
	"strings"
)

type Formatter interface {
	Encrypt(content []byte, keys []string, encryptFn func([]byte) (string, error)) ([]byte, error)
	Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error)
	// Extract returns one value, addressed by a dot-separated path, decrypting it if needed.
	Extract(content []byte, path string, decryptFn func(string) ([]byte, error)) ([]byte, error)
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

func splitPath(path string) []string {
	return strings.Split(path, ".")
}

func notFound(path string) error {
	return fmt.Errorf("key %q not found", path)
}

func notScalar(path string) error {
	return fmt.Errorf("key %q is not a single value", path)
}
