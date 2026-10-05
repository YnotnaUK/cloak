package formats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ynotnauk/cloak/internal/crypto"
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
				if strings.HasPrefix(val, crypto.Prefix) {
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
			if strings.HasPrefix(val, crypto.Prefix) {
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

func (j *JsonFormatter) Extract(content []byte, path string, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	var cur any
	if err := dec.Decode(&cur); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	for _, part := range splitPath(path) {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, notFound(path)
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, notFound(path)
			}
			cur = node[idx]
		default:
			return nil, notFound(path)
		}
	}

	switch v := cur.(type) {
	case map[string]any, []any:
		return nil, notScalar(path)
	case string:
		if strings.HasPrefix(v, crypto.Prefix) {
			return decryptFn(v)
		}
		return []byte(v), nil
	default:
		return []byte(fmt.Sprintf("%v", v)), nil
	}
}
