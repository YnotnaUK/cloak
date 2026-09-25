package formats

import (
	"encoding/json"
	"fmt"
	"strings"
)

type JsonFormatter struct{}

func (j *JsonFormatter) Encrypt(content []byte, targetKeys []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	keySet := make(map[string]bool, len(targetKeys))
	for _, k := range targetKeys {
		keySet[k] = true
	}

	if err := walkMapEncrypt(data, keySet, encryptFn); err != nil {
		return nil, err
	}

	return json.MarshalIndent(data, "", "  ")
}

func (j *JsonFormatter) Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	if err := walkMapDecrypt(data, decryptFn); err != nil {
		return nil, err
	}

	return json.MarshalIndent(data, "", "  ")
}

func walkMapEncrypt(m map[string]any, keys map[string]bool, encryptFn func([]byte) (string, error)) error {
	for k, v := range m {
		switch val := v.(type) {
		case map[string]any:
			if err := walkMapEncrypt(val, keys, encryptFn); err != nil {
				return err
			}
		case string:
			if keys[k] {
				if strings.HasPrefix(val, "CLOAK:v1:") {
					continue // Already encrypted
				}
				enc, err := encryptFn([]byte(val))
				if err != nil {
					return fmt.Errorf("failed encrypting key %s: %w", k, err)
				}
				m[k] = enc
			}
		default:
			if keys[k] {
				enc, err := encryptFn([]byte(fmt.Sprintf("%v", val)))
				if err != nil {
					return fmt.Errorf("failed encrypting key %s: %w", k, err)
				}
				m[k] = enc
			}
		}
	}
	return nil
}

func walkMapDecrypt(m map[string]any, decryptFn func(string) ([]byte, error)) error {
	for k, v := range m {
		switch val := v.(type) {
		case map[string]any:
			if err := walkMapDecrypt(val, decryptFn); err != nil {
				return err
			}
		case string:
			if strings.HasPrefix(val, "CLOAK:v1:") {
				dec, err := decryptFn(val)
				if err != nil {
					return fmt.Errorf("failed decrypting key %s: %w", k, err)
				}
				m[k] = string(dec)
			}
		}
	}
	return nil
}
