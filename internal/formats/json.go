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
	var data any
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	keySet := make(map[string]bool, len(targetKeys))
	for _, k := range targetKeys {
		keySet[k] = true
	}

	if err := walkEncrypt(data, keySet, encryptFn); err != nil {
		return nil, err
	}

	return json.MarshalIndent(data, "", "  ")
}

func (j *JsonFormatter) Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	var data any
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	if err := walkDecrypt(data, decryptFn); err != nil {
		return nil, err
	}

	return json.MarshalIndent(data, "", "  ")
}

func walkEncrypt(v any, keys map[string]bool, encryptFn func([]byte) (string, error)) error {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			if !keys[k] {
				if err := walkEncrypt(child, keys, encryptFn); err != nil {
					return err
				}
				continue
			}
			switch c := child.(type) {
			case string:
				if strings.HasPrefix(c, crypto.Prefix) {
					continue // Already encrypted
				}
				enc, err := encryptFn([]byte(c))
				if err != nil {
					return fmt.Errorf("failed encrypting key %s: %w", k, err)
				}
				val[k] = enc
			case map[string]any:
				if err := walkEncrypt(c, keys, encryptFn); err != nil {
					return err
				}
			default:
				enc, err := encryptFn([]byte(fmt.Sprintf("%v", c)))
				if err != nil {
					return fmt.Errorf("failed encrypting key %s: %w", k, err)
				}
				val[k] = enc
			}
		}
	case []any:
		for _, child := range val {
			if err := walkEncrypt(child, keys, encryptFn); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkDecrypt(v any, decryptFn func(string) ([]byte, error)) error {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			if s, ok := child.(string); ok {
				if strings.HasPrefix(s, crypto.Prefix) {
					dec, err := decryptFn(s)
					if err != nil {
						return fmt.Errorf("failed decrypting key %s: %w", k, err)
					}
					val[k] = string(dec)
				}
				continue
			}
			if err := walkDecrypt(child, decryptFn); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range val {
			if err := walkDecrypt(child, decryptFn); err != nil {
				return err
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
