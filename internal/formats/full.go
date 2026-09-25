package formats

import "strings"

type FullFormatter struct{}

func (f *FullFormatter) Encrypt(content []byte, _ []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
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
