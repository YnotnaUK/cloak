package formats

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ynotnauk/cloak/internal/envelope"
	"gopkg.in/yaml.v3"
)

// HasEncrypted reports whether content contains an envelope in a field that
// the formatter would encrypt. Malformed reserved-prefix values in those
// fields are errors; unrelated values and comments do not trigger rekeying.
func HasEncrypted(formatType string, content []byte, targetKeys []string) (bool, error) {
	keySet := make(map[string]bool, len(targetKeys))
	for _, key := range targetKeys {
		keySet[key] = true
	}

	switch formatType {
	case "yaml":
		docs, err := decodeYamlDocs(content)
		if err != nil {
			return false, err
		}
		for _, doc := range docs {
			found, err := yamlHasEncrypted(doc, keySet)
			if err != nil || found {
				return found, err
			}
		}
		return false, nil
	case "json":
		value, err := decodeJSON(content)
		if err != nil {
			return false, err
		}
		return jsonHasEncrypted(value, keySet)
	case "env":
		scanner := newEnvScanner(content)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok || !keySet[strings.TrimSpace(key)] {
				continue
			}
			found, err := checkEnvelope(strings.TrimSpace(value))
			if err != nil || found {
				return found, err
			}
		}
		if err := scanner.Err(); err != nil {
			return false, err
		}
		return false, nil
	case "full":
		return checkEnvelope(strings.TrimSpace(string(content)))
	default:
		return false, fmt.Errorf("unsupported format type: %s", formatType)
	}
}

// Rekey replaces ciphertext in configured fields without decrypting envelopes
// in other fields. Plaintext configured fields are left unchanged.
func Rekey(formatType string, content []byte, targetKeys []string, decryptFn func(string) ([]byte, error), encryptFn func([]byte) (string, error)) ([]byte, error) {
	keySet := make(map[string]bool, len(targetKeys))
	for _, key := range targetKeys {
		keySet[key] = true
	}

	switch formatType {
	case "yaml":
		docs, err := decodeYamlDocs(content)
		if err != nil {
			return nil, err
		}
		for _, doc := range docs {
			if err := yamlRekey(doc, keySet, decryptFn, encryptFn); err != nil {
				return nil, err
			}
		}
		return encodeYamlDocs(docs)
	case "json":
		return rekeyJSON(content, keySet, decryptFn, encryptFn)
	case "env":
		return rekeyEnv(content, keySet, decryptFn, encryptFn)
	case "full":
		value := strings.TrimSpace(string(content))
		found, err := checkEnvelope(value)
		if err != nil || !found {
			return content, err
		}
		plain, err := decryptFn(value)
		if err != nil {
			return nil, err
		}
		ciphertext, err := encryptFn(plain)
		if err != nil {
			return nil, err
		}
		return []byte(ciphertext + "\n"), nil
	default:
		return nil, fmt.Errorf("unsupported format type: %s", formatType)
	}
}

func yamlHasEncrypted(node *yaml.Node, keys map[string]bool) (bool, error) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if value.Kind == yaml.ScalarNode && keys[key.Value] {
				found, err := checkEnvelope(value.Value)
				if err != nil || found {
					return found, err
				}
			}
			found, err := yamlHasEncrypted(value, keys)
			if err != nil || found {
				return found, err
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			found, err := yamlHasEncrypted(child, keys)
			if err != nil || found {
				return found, err
			}
		}
	}
	return false, nil
}

func yamlRekey(node *yaml.Node, keys map[string]bool, decryptFn func(string) ([]byte, error), encryptFn func([]byte) (string, error)) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if keys[key.Value] && value.Kind == yaml.ScalarNode {
				found, err := checkEnvelope(value.Value)
				if err != nil {
					return fmt.Errorf("YAML scalar %q: %w", key.Value, err)
				}
				if found {
					plain, err := decryptFn(value.Value)
					if err != nil {
						return fmt.Errorf("failed decrypting YAML scalar %q for rekey: %w", key.Value, err)
					}
					value.Value, err = encryptFn(plain)
					if err != nil {
						return fmt.Errorf("failed re-encrypting YAML scalar %q: %w", key.Value, err)
					}
				}
			}
			if err := yamlRekey(value, keys, decryptFn, encryptFn); err != nil {
				return err
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			if err := yamlRekey(child, keys, decryptFn, encryptFn); err != nil {
				return err
			}
		}
	}
	return nil
}

func jsonHasEncrypted(value any, keys map[string]bool) (bool, error) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if keys[key] {
				if text, ok := child.(string); ok {
					found, err := checkEnvelope(text)
					if err != nil || found {
						return found, err
					}
				}
			}
			found, err := jsonHasEncrypted(child, keys)
			if err != nil || found {
				return found, err
			}
		}
	case []any:
		for _, child := range value {
			found, err := jsonHasEncrypted(child, keys)
			if err != nil || found {
				return found, err
			}
		}
	}
	return false, nil
}

func rekeyJSON(content []byte, keys map[string]bool, decryptFn func(string) ([]byte, error), encryptFn func([]byte) (string, error)) ([]byte, error) {
	return rewriteJSONSelected(content, keys, true, true, func(raw []byte) ([]byte, bool, error) {
		value, err := decodeJSON(raw)
		if err != nil {
			return nil, false, err
		}
		ciphertext, ok := value.(string)
		if !ok {
			return nil, false, nil
		}
		found, err := checkEnvelope(ciphertext)
		if err != nil || !found {
			return nil, false, err
		}
		plain, err := decryptFn(ciphertext)
		if err != nil {
			return nil, false, err
		}
		rekeyed, err := encryptFn(plain)
		if err != nil {
			return nil, false, err
		}
		encoded, err := encodeJSONString(rekeyed)
		return encoded, true, err
	})
}

func rekeyEnv(content []byte, keys map[string]bool, decryptFn func(string) ([]byte, error), encryptFn func([]byte) (string, error)) ([]byte, error) {
	scanner := newEnvScanner(content)
	var out bytes.Buffer
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !keys[key] {
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}
		value = strings.TrimSpace(value)
		found, err := checkEnvelope(value)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", key, err)
		}
		if !found {
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}
		plain, err := decryptFn(value)
		if err != nil {
			return nil, fmt.Errorf("failed decrypting key %s for rekey: %w", key, err)
		}
		ciphertext, err := encryptFn(plain)
		if err != nil {
			return nil, fmt.Errorf("failed re-encrypting key %s: %w", key, err)
		}
		out.WriteString(key)
		out.WriteByte('=')
		out.WriteString(ciphertext)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func checkEnvelope(value string) (bool, error) {
	return envelope.Check(value)
}
