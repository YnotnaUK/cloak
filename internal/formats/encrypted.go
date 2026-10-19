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
		for _, line := range splitEnvLines(content) {
			if isEnvCommentOrEmpty(line.text) {
				continue
			}
			assignment, ok := parseEnvAssignment(line.text)
			if !ok || !keySet[assignment.key] {
				continue
			}
			value := line.text[assignment.valueStart:assignment.valueEnd]
			found, err := checkEnvelope(string(value))
			if err != nil || found {
				return found, err
			}
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
	return yamlHasEncryptedNode(node, keys, make(map[*yaml.Node]bool), make(map[*yaml.Node]bool))
}

func yamlHasEncryptedNode(node *yaml.Node, keys map[string]bool, visiting, completed map[*yaml.Node]bool) (bool, error) {
	if visiting[node] {
		return false, fmt.Errorf("YAML alias cycle detected")
	}
	if completed[node] {
		return false, nil
	}
	visiting[node] = true
	defer delete(visiting, node)

	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if keys[key.Value] {
				target, err := resolveYamlAlias(value)
				if err != nil {
					return false, fmt.Errorf("YAML key %q: %w", key.Value, err)
				}
				if target.Kind == yaml.ScalarNode {
					found, err := checkEnvelope(target.Value)
					if err != nil || found {
						return found, err
					}
				}
			}
			found, err := yamlHasEncryptedNode(value, keys, visiting, completed)
			if err != nil || found {
				return found, err
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			found, err := yamlHasEncryptedNode(child, keys, visiting, completed)
			if err != nil || found {
				return found, err
			}
		}
	case yaml.AliasNode:
		if node.Alias == nil {
			return false, fmt.Errorf("YAML alias has no target")
		}
		found, err := yamlHasEncryptedNode(node.Alias, keys, visiting, completed)
		if err != nil || found {
			return found, err
		}
	}
	completed[node] = true
	return false, nil
}

func yamlRekey(node *yaml.Node, keys map[string]bool, decryptFn func(string) ([]byte, error), encryptFn func([]byte) (string, error)) error {
	return yamlRekeyNode(node, keys, decryptFn, encryptFn, make(map[*yaml.Node]bool), make(map[*yaml.Node]bool), make(map[*yaml.Node]bool))
}

func yamlRekeyNode(node *yaml.Node, keys map[string]bool, decryptFn func(string) ([]byte, error), encryptFn func([]byte) (string, error), visiting, rekeyed, completed map[*yaml.Node]bool) error {
	if visiting[node] {
		return fmt.Errorf("YAML alias cycle detected")
	}
	if completed[node] {
		return nil
	}
	visiting[node] = true
	defer delete(visiting, node)

	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if keys[key.Value] {
				target, err := resolveYamlAlias(value)
				if err != nil {
					return fmt.Errorf("YAML key %q: %w", key.Value, err)
				}
				if target.Kind == yaml.ScalarNode && !rekeyed[target] {
					found, err := checkEnvelope(target.Value)
					if err != nil {
						return fmt.Errorf("YAML scalar %q: %w", key.Value, err)
					}
					if found {
						plain, err := decryptFn(target.Value)
						if err != nil {
							return fmt.Errorf("failed decrypting YAML scalar %q for rekey: %w", key.Value, err)
						}
						target.Value, err = encryptFn(plain)
						if err != nil {
							return fmt.Errorf("failed re-encrypting YAML scalar %q: %w", key.Value, err)
						}
						rekeyed[target] = true
					}
				}
			}
			if err := yamlRekeyNode(value, keys, decryptFn, encryptFn, visiting, rekeyed, completed); err != nil {
				return err
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			if err := yamlRekeyNode(child, keys, decryptFn, encryptFn, visiting, rekeyed, completed); err != nil {
				return err
			}
		}
	case yaml.AliasNode:
		if node.Alias == nil {
			return fmt.Errorf("YAML alias has no target")
		}
		if err := yamlRekeyNode(node.Alias, keys, decryptFn, encryptFn, visiting, rekeyed, completed); err != nil {
			return err
		}
	}
	completed[node] = true
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
	var out bytes.Buffer
	for _, line := range splitEnvLines(content) {
		if isEnvCommentOrEmpty(line.text) {
			writeEnvLine(&out, line, line.text)
			continue
		}
		assignment, ok := parseEnvAssignment(line.text)
		if !ok || !keys[assignment.key] {
			writeEnvLine(&out, line, line.text)
			continue
		}
		value := line.text[assignment.valueStart:assignment.valueEnd]
		found, err := checkEnvelope(string(value))
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", assignment.key, err)
		}
		if !found {
			writeEnvLine(&out, line, line.text)
			continue
		}
		plain, err := decryptFn(string(value))
		if err != nil {
			return nil, fmt.Errorf("failed decrypting key %s for rekey: %w", assignment.key, err)
		}
		ciphertext, err := encryptFn(plain)
		if err != nil {
			return nil, fmt.Errorf("failed re-encrypting key %s: %w", assignment.key, err)
		}
		updated := make([]byte, 0, len(line.text)+len(ciphertext)-len(value))
		updated = append(updated, line.text[:assignment.valueStart]...)
		updated = append(updated, ciphertext...)
		updated = append(updated, line.text[assignment.valueEnd:]...)
		writeEnvLine(&out, line, updated)
	}
	return out.Bytes(), nil
}

func checkEnvelope(value string) (bool, error) {
	return envelope.Check(value)
}
