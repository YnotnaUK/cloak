package formats

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type YamlFormatter struct{}

func (y *YamlFormatter) Encrypt(content []byte, targetKeys []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("invalid yaml: %w", err)
	}

	keySet := make(map[string]bool, len(targetKeys))
	for _, k := range targetKeys {
		keySet[k] = true
	}

	if err := walkYamlEncrypt(&root, keySet, encryptFn); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (y *YamlFormatter) Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("invalid yaml: %w", err)
	}

	if err := walkYamlDecrypt(&root, decryptFn); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func walkYamlEncrypt(node *yaml.Node, keys map[string]bool, encryptFn func([]byte) (string, error)) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valNode := node.Content[i+1]

			if keys[keyNode.Value] && valNode.Kind == yaml.ScalarNode {
				enc, err := encryptFn([]byte(valNode.Value))
				if err != nil {
					return err
				}
				valNode.Value = enc
				valNode.Tag = "!!str"
			} else {
				if err := walkYamlEncrypt(valNode, keys, encryptFn); err != nil {
					return err
				}
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			if err := walkYamlEncrypt(child, keys, encryptFn); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkYamlDecrypt(node *yaml.Node, decryptFn func(string) ([]byte, error)) error {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			valNode := node.Content[i+1]
			if valNode.Kind == yaml.ScalarNode && strings.HasPrefix(valNode.Value, "CLOAK:v1:") {
				dec, err := decryptFn(valNode.Value)
				if err != nil {
					return err
				}
				valNode.Value = string(dec)
			} else {
				if err := walkYamlDecrypt(valNode, decryptFn); err != nil {
					return err
				}
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			if err := walkYamlDecrypt(child, decryptFn); err != nil {
				return err
			}
		}
	}
	return nil
}
