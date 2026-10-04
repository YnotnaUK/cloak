package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	EnvKey     = "CLOAK_KEY"
	EnvKeyFile = "CLOAK_KEY_FILE"
)

// Options controls where and how a keypair is generated.
type Options struct {
	Path   string // custom output file; defaults to the user config directory
	Stdout bool   // emit the key file content instead of writing to disk
	Name   string // optional label stored in the key file header
	Force  bool   // overwrite an existing file
}

// Result describes a generated keypair.
type Result struct {
	PublicKey string
	Content   string // full key file content
	Path      string // empty when Stdout is set
}

func defaultKeyPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config dir: %w", err)
	}
	return filepath.Join(configDir, "cloak", "key.txt"), nil
}

// Generate creates a new X25519 keypair and writes it to disk unless opts.Stdout is set.
func Generate(opts Options) (*Result, error) {
	if opts.Stdout && opts.Path != "" {
		return nil, errors.New("--stdout and --out cannot be combined")
	}
	if strings.ContainsAny(opts.Name, "\r\n") {
		return nil, errors.New("key name must not contain line breaks")
	}

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	pubHex := hex.EncodeToString(privKey.PublicKey().Bytes())
	privHex := hex.EncodeToString(privKey.Bytes())

	var b strings.Builder
	if opts.Name != "" {
		fmt.Fprintf(&b, "# Name: %s\n", strings.TrimSpace(opts.Name))
	}
	fmt.Fprintf(&b, "# Created: %s\n", time.Now().Format("02/01/2006"))
	fmt.Fprintf(&b, "# Public Key: %s\n%s\n", pubHex, privHex)
	res := &Result{PublicKey: pubHex, Content: b.String()}

	if opts.Stdout {
		return res, nil
	}

	path := opts.Path
	if path == "" {
		if path, err = defaultKeyPath(); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	flags := os.O_WRONLY | os.O_CREATE
	if opts.Force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("key file already exists at %s (use -f or --force to overwrite)", path)
		}
		return nil, fmt.Errorf("failed to create key file: %w", err)
	}
	if _, err := f.WriteString(res.Content); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to write key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to write key: %w", err)
	}

	res.Path = path
	return res, nil
}

// ReadPublicKey extracts the public key from the default key file.
func ReadPublicKey() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config dir: %w", err)
	}

	keyFilePath := filepath.Join(configDir, "cloak", "key.txt")
	data, err := os.ReadFile(keyFilePath)
	if err != nil {
		return "", fmt.Errorf("could not read key file (run 'cloak keygen' first): %w", err)
	}

	// Parse the first comment line: "# Public Key: <hex>"
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# Public Key:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# Public Key:")), nil
		}
	}

	return "", errors.New("public key not found in key file")
}

// ReadPrivateKey resolves the private key from CLOAK_KEY, then CLOAK_KEY_FILE,
// then the default key file.
func ReadPrivateKey() (string, error) {
	if v := strings.TrimSpace(os.Getenv(EnvKey)); v != "" {
		return parsePrivateKey(v)
	}

	path := strings.TrimSpace(os.Getenv(EnvKeyFile))
	if path == "" {
		var err error
		if path, err = defaultKeyPath(); err != nil {
			return "", err
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("could not read key file (set %s, %s or run 'cloak keygen'): %w", EnvKey, EnvKeyFile, err)
	}
	return parsePrivateKey(string(data))
}

// parsePrivateKey accepts either a bare hex key or full key file content.
func parsePrivateKey(data string) (string, error) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line, nil
		}
	}
	return "", errors.New("private key not found")
}
