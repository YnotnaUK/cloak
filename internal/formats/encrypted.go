package formats

import (
	"bufio"
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
		var root yaml.Node
		if err := yaml.Unmarshal(content, &root); err != nil {
			return false, fmt.Errorf("invalid yaml: %w", err)
		}
		return yamlHasEncrypted(&root, keySet)
	case "json":
		value, err := decodeJSON(content)
		if err != nil {
			return false, err
		}
		return jsonHasEncrypted(value, keySet)
	case "env":
		scanner := bufio.NewScanner(bytes.NewReader(content))
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

func checkEnvelope(value string) (bool, error) {
	return envelope.Check(value)
}
