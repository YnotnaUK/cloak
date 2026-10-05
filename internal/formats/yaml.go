package formats

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ynotnauk/cloak/internal/crypto"
	"gopkg.in/yaml.v3"
)

type YamlFormatter struct{}

func (y *YamlFormatter) Encrypt(content []byte, targetKeys []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	docs, err := decodeYamlDocs(content)
	if err != nil {
		return nil, err
	}

	keySet := make(map[string]bool, len(targetKeys))
	for _, k := range targetKeys {
		keySet[k] = true
	}

	for _, doc := range docs {
		if err := walkYamlEncrypt(doc, keySet, encryptFn); err != nil {
			return nil, err
		}
	}
	return encodeYamlDocs(docs)
}

func (y *YamlFormatter) Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	docs, err := decodeYamlDocs(content)
	if err != nil {
		return nil, err
	}

	for _, doc := range docs {
		if err := walkYamlDecrypt(doc, decryptFn); err != nil {
			return nil, err
		}
	}
	return encodeYamlDocs(docs)
}

func decodeYamlDocs(content []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(content))
	var docs []*yaml.Node
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				return docs, nil
			}
			return nil, fmt.Errorf("invalid yaml: %w", err)
		}
		docs = append(docs, &doc)
	}
}

func encodeYamlDocs(docs []*yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	for _, doc := range docs {
		if err := enc.Encode(doc); err != nil {
			return nil, err
		}
	}
	if err := enc.Close(); err != nil {
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
				if strings.HasPrefix(valNode.Value, crypto.Prefix) {
					continue // Already encrypted
				}

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
			if valNode.Kind == yaml.ScalarNode && strings.HasPrefix(valNode.Value, crypto.Prefix) {
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

func (y *YamlFormatter) Extract(content []byte, path string, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("invalid yaml: %w", err)
	}

	cur := &root
	if cur.Kind == yaml.DocumentNode && len(cur.Content) > 0 {
		cur = cur.Content[0]
	}

	for _, part := range splitPath(path) {
		for cur.Kind == yaml.AliasNode && cur.Alias != nil {
			cur = cur.Alias
		}
		switch cur.Kind {
		case yaml.MappingNode:
			var next *yaml.Node
			for i := 0; i+1 < len(cur.Content); i += 2 {
				if cur.Content[i].Value == part {
					next = cur.Content[i+1]
					break
				}
			}
			if next == nil {
				return nil, notFound(path)
			}
			cur = next
		case yaml.SequenceNode:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(cur.Content) {
				return nil, notFound(path)
			}
			cur = cur.Content[idx]
		default:
			return nil, notFound(path)
		}
	}

	for cur.Kind == yaml.AliasNode && cur.Alias != nil {
		cur = cur.Alias
	}
	if cur.Kind != yaml.ScalarNode {
		return nil, notScalar(path)
	}
	if strings.HasPrefix(cur.Value, crypto.Prefix) {
		return decryptFn(cur.Value)
	}
	return []byte(cur.Value), nil
}
