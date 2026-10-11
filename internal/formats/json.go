package formats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ynotnauk/cloak/internal/crypto"
)

type JsonFormatter struct{}

func (j *JsonFormatter) Encrypt(content []byte, targetKeys []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	data, err := decodeJSON(content)
	if err != nil {
		return nil, err
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
	data, err := decodeJSON(content)
	if err != nil {
		return nil, err
	}

	if err := walkDecrypt(data, decryptFn); err != nil {
		return nil, err
	}

	return json.MarshalIndent(data, "", "  ")
}

// jsonPayloadMarker prefixes plaintext that holds the JSON encoding of a
// non-string value, so decryption can restore the original type.
const jsonPayloadMarker = "\x00json:"

func decodeJSON(content []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	var data any
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("invalid json: unexpected data after top-level value")
	}
	return data, nil
}

func encodeJSONPayload(v any) ([]byte, error) {
	if s, ok := v.(string); ok && !strings.HasPrefix(s, jsonPayloadMarker) {
		return []byte(s), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append([]byte(jsonPayloadMarker), b...), nil
}

func decodeJSONPayload(plain []byte) (any, error) {
	rest, ok := strings.CutPrefix(string(plain), jsonPayloadMarker)
	if !ok {
		return string(plain), nil
	}
	return decodeJSON([]byte(rest))
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
			if c, ok := child.(string); ok && strings.HasPrefix(c, crypto.Prefix) {
				continue // Already encrypted
			}
			if c, ok := child.(map[string]any); ok {
				if err := walkEncrypt(c, keys, encryptFn); err != nil {
					return err
				}
				continue
			}
			payload, err := encodeJSONPayload(child)
			if err != nil {
				return fmt.Errorf("failed encoding key %s: %w", k, err)
			}
			enc, err := encryptFn(payload)
			if err != nil {
				return fmt.Errorf("failed encrypting key %s: %w", k, err)
			}
			val[k] = enc
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
					restored, err := decodeJSONPayload(dec)
					if err != nil {
						return fmt.Errorf("failed decoding key %s: %w", k, err)
					}
					val[k] = restored
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
	cur, err := decodeJSON(content)
	if err != nil {
		return nil, err
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
			plain, err := decryptFn(v)
			if err != nil {
				return nil, err
			}
			restored, err := decodeJSONPayload(plain)
			if err != nil {
				return nil, err
			}
			switch r := restored.(type) {
			case string:
				return []byte(r), nil
			case map[string]any, []any, nil:
				return json.Marshal(r)
			default:
				return []byte(fmt.Sprintf("%v", r)), nil
			}
		}
		return []byte(v), nil
	default:
		return []byte(fmt.Sprintf("%v", v)), nil
	}
}
