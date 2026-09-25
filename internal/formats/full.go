package formats

import (
	"strings"

	"github.com/ynotnauk/cloak/internal/crypto"
)

type FullFormatter struct{}

func (f *FullFormatter) Encrypt(content []byte, _ []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	trimmed := strings.TrimSpace(string(content))
	if strings.HasPrefix(trimmed, crypto.Prefix) {
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
	return decryptFn(encStr)
}
