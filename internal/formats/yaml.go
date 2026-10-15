package formats

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/ynotnauk/cloak/internal/envelope"
	"gopkg.in/yaml.v3"
)

type YamlFormatter struct{}

type yamlScalarPayload struct {
	Tag   string
	Style yaml.Style
	Value string
}

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
				encrypted, err := envelope.Check(valNode.Value)
				if err != nil {
					return fmt.Errorf("YAML scalar %q: %w", keyNode.Value, err)
				}
				if encrypted {
					continue // Already encrypted
				}

				payload, err := json.Marshal(struct {
					Tag   string     `json:"tag"`
					Style yaml.Style `json:"style"`
					Value string     `json:"value"`
				}{Tag: valNode.Tag, Style: valNode.Style, Value: valNode.Value})
				if err != nil {
					return fmt.Errorf("failed encoding YAML scalar %q: %w", keyNode.Value, err)
				}
				enc, err := encryptFn(payload)
				if err != nil {
					return fmt.Errorf("failed encrypting YAML scalar %q: %w", keyNode.Value, err)
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
			keyNode := node.Content[i]
			valNode := node.Content[i+1]
			encrypted := false
			if valNode.Kind == yaml.ScalarNode {
				var err error
				if encrypted, err = envelope.Check(valNode.Value); err != nil {
					return fmt.Errorf("YAML scalar %q: %w", keyNode.Value, err)
				}
			}
			if encrypted {
				dec, err := decryptFn(valNode.Value)
				if err != nil {
					return fmt.Errorf("failed decrypting YAML scalar %q: %w", keyNode.Value, err)
				}
				payload, err := decodeYamlScalarPayload(dec)
				if err != nil {
					return fmt.Errorf("failed decoding YAML scalar %q: %w", keyNode.Value, err)
				}
				valNode.Value = payload.Value
				valNode.Tag = payload.Tag
				valNode.Style = payload.Style
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
	encrypted, err := envelope.Check(cur.Value)
	if err != nil {
		return nil, err
	}
	if encrypted {
		plain, err := decryptFn(cur.Value)
		if err != nil {
			return nil, err
		}
		payload, err := decodeYamlScalarPayload(plain)
		if err != nil {
			return nil, err
		}
		return []byte(payload.Value), nil
	}
	return []byte(cur.Value), nil
}

func decodeYamlScalarPayload(plain []byte) (yamlScalarPayload, error) {
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	var encoded struct {
		Tag   *string     `json:"tag"`
		Style *yaml.Style `json:"style"`
		Value *string     `json:"value"`
	}
	if err := dec.Decode(&encoded); err != nil {
		return yamlScalarPayload{}, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		if err == nil {
			return yamlScalarPayload{}, fmt.Errorf("unexpected data after YAML scalar payload")
		}
		return yamlScalarPayload{}, fmt.Errorf("invalid trailing JSON: %w", err)
	}
	if encoded.Tag == nil || encoded.Style == nil || encoded.Value == nil {
		return yamlScalarPayload{}, fmt.Errorf("YAML scalar payload must include string tag, numeric style, and string value")
	}
	if *encoded.Tag == "" {
		return yamlScalarPayload{}, fmt.Errorf("YAML scalar payload tag cannot be empty")
	}
	const validStyles = yaml.TaggedStyle | yaml.DoubleQuotedStyle | yaml.SingleQuotedStyle | yaml.LiteralStyle | yaml.FoldedStyle | yaml.FlowStyle
	if (*encoded.Style & ^validStyles) != 0 {
		return yamlScalarPayload{}, fmt.Errorf("YAML scalar payload has invalid style %d", *encoded.Style)
	}
	return yamlScalarPayload{Tag: *encoded.Tag, Style: *encoded.Style, Value: *encoded.Value}, nil
}
