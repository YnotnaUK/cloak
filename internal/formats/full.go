package formats

import (
	"fmt"
	"strings"

	"github.com/ynotnauk/cloak/internal/envelope"
)

type FullFormatter struct{}

func (f *FullFormatter) Encrypt(content []byte, _ []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	trimmed := strings.TrimSpace(string(content))
	encrypted, err := envelope.Check(trimmed)
	if err != nil {
		return nil, err
	}
	if encrypted {
		return content, nil // Already encrypted
	}

	enc, err := encryptFn(content)
	if err != nil {
		return nil, err
	}
	return []byte(enc + "\n"), nil
}

func (f *FullFormatter) Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	encStr := strings.TrimSpace(string(content))
	encrypted, err := envelope.Check(encStr)
	if err != nil {
		return nil, err
	}
	if !encrypted {
		return content, nil // Already decrypted / plaintext
	}
	return decryptFn(encStr)
}

func (f *FullFormatter) Extract(_ []byte, _ string, _ func(string) ([]byte, error)) ([]byte, error) {
	return nil, fmt.Errorf("--extract is not supported for full-file rules; decrypt the whole file instead")
}
