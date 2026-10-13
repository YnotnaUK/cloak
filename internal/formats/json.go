package formats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ynotnauk/cloak/internal/envelope"
)

type JsonFormatter struct{}

func (j *JsonFormatter) Encrypt(content []byte, targetKeys []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	keySet := make(map[string]bool, len(targetKeys))
	for _, k := range targetKeys {
		keySet[k] = true
	}

	return rewriteJSON(content, keySet, false, func(raw []byte) ([]byte, bool, error) {
		value, err := decodeJSON(raw)
		if err != nil {
			return nil, false, err
		}
		if s, ok := value.(string); ok {
			encrypted, err := envelope.Check(s)
			if err != nil {
				return nil, false, err
			}
			if encrypted {
				return nil, false, nil
			}
		}
		return encryptValue(append([]byte(jsonPayloadMarker), raw...), encryptFn)
	})
}

func (j *JsonFormatter) Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	return rewriteJSON(content, nil, true, func(raw []byte) ([]byte, bool, error) {
		value, err := decodeJSON(raw)
		if err != nil {
			return nil, false, err
		}
		s, ok := value.(string)
		if !ok {
			return nil, false, nil
		}
		encrypted, err := envelope.Check(s)
		if err != nil {
			return nil, false, err
		}
		if !encrypted {
			return nil, false, nil
		}
		plain, err := decryptFn(s)
		if err != nil {
			return nil, false, err
		}
		if payload, ok := strings.CutPrefix(string(plain), jsonPayloadMarker); ok {
			if _, err := decodeJSON([]byte(payload)); err != nil {
				return nil, false, fmt.Errorf("invalid encrypted JSON payload: %w", err)
			}
			return []byte(payload), true, nil
		}
		encoded, err := encodeJSONString(string(plain))
		return encoded, true, err
	})
}

func encryptValue(plain []byte, encryptFn func([]byte) (string, error)) ([]byte, bool, error) {
	encrypted, err := encryptFn(plain)
	if err != nil {
		return nil, false, err
	}
	encoded, err := encodeJSONString(encrypted)
	return encoded, true, err
}

func encodeJSONString(value string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

type jsonReplacement struct {
	start int
	end   int
	value []byte
}

type jsonScanner struct {
	content      []byte
	offset       int
	keys         map[string]bool
	decrypt      bool
	transform    func([]byte) ([]byte, bool, error)
	replacements []jsonReplacement
}

func rewriteJSON(content []byte, keys map[string]bool, decrypt bool, transform func([]byte) ([]byte, bool, error)) ([]byte, error) {
	if _, err := decodeJSON(content); err != nil {
		return nil, err
	}
	scanner := jsonScanner{content: content, keys: keys, decrypt: decrypt, transform: transform}
	if err := scanner.rewriteValue("", false); err != nil {
		return nil, err
	}
	scanner.skipWhitespace()
	if scanner.offset != len(content) {
		return nil, fmt.Errorf("invalid json: unexpected data after top-level value")
	}
	if len(scanner.replacements) == 0 {
		return content, nil
	}

	var out bytes.Buffer
	pos := 0
	for _, replacement := range scanner.replacements {
		out.Write(content[pos:replacement.start])
		out.Write(replacement.value)
		pos = replacement.end
	}
	out.Write(content[pos:])
	return out.Bytes(), nil
}

func (s *jsonScanner) rewriteValue(key string, objectValue bool) error {
	s.skipWhitespace()
	start := s.offset
	if start >= len(s.content) {
		return fmt.Errorf("invalid json: expected value")
	}

	targeted := !s.decrypt && objectValue && s.keys[key]
	if targeted && s.content[start] != '{' {
		if err := s.consumeValue(); err != nil {
			return err
		}
		replacement, changed, err := s.transform(s.content[start:s.offset])
		if err != nil {
			return fmt.Errorf("failed processing key %s: %w", key, err)
		}
		if changed {
			s.replacements = append(s.replacements, jsonReplacement{start: start, end: s.offset, value: replacement})
		}
		return nil
	}

	switch s.content[start] {
	case '{':
		return s.rewriteObject()
	case '[':
		return s.rewriteArray()
	default:
		if err := s.consumeValue(); err != nil {
			return err
		}
		if s.decrypt && objectValue && s.content[start] == '"' {
			replacement, changed, err := s.transform(s.content[start:s.offset])
			if err != nil {
				return fmt.Errorf("failed processing key %s: %w", key, err)
			}
			if changed {
				s.replacements = append(s.replacements, jsonReplacement{start: start, end: s.offset, value: replacement})
			}
		}
		return nil
	}
}

func (s *jsonScanner) rewriteObject() error {
	s.offset++
	s.skipWhitespace()
	if s.take('}') {
		return nil
	}
	for {
		s.skipWhitespace()
		key, err := s.readString()
		if err != nil {
			return err
		}
		s.skipWhitespace()
		if !s.take(':') {
			return fmt.Errorf("invalid json: expected colon")
		}
		if err := s.rewriteValue(key, true); err != nil {
			return err
		}
		s.skipWhitespace()
		if s.take('}') {
			return nil
		}
		if !s.take(',') {
			return fmt.Errorf("invalid json: expected comma or closing brace")
		}
	}
}

func (s *jsonScanner) rewriteArray() error {
	s.offset++
	s.skipWhitespace()
	if s.take(']') {
		return nil
	}
	for {
		if err := s.rewriteValue("", false); err != nil {
			return err
		}
		s.skipWhitespace()
		if s.take(']') {
			return nil
		}
		if !s.take(',') {
			return fmt.Errorf("invalid json: expected comma or closing bracket")
		}
	}
}

func (s *jsonScanner) consumeValue() error {
	s.skipWhitespace()
	if s.offset >= len(s.content) {
		return fmt.Errorf("invalid json: expected value")
	}
	switch s.content[s.offset] {
	case '{':
		return s.consumeContainer()
	case '[':
		return s.consumeContainer()
	case '"':
		_, err := s.readString()
		return err
	default:
		start := s.offset
		for s.offset < len(s.content) && !isJSONDelimiter(s.content[s.offset]) {
			s.offset++
		}
		if s.offset == start {
			return fmt.Errorf("invalid json: expected value")
		}
		return nil
	}
}

func (s *jsonScanner) consumeContainer() error {
	close := byte('}')
	if s.content[s.offset] == '[' {
		close = ']'
	}
	s.offset++
	stack := []byte{close}
	for s.offset < len(s.content) && len(stack) > 0 {
		switch s.content[s.offset] {
		case '"':
			if _, err := s.readString(); err != nil {
				return err
			}
		case '{':
			stack = append(stack, '}')
			s.offset++
		case '[':
			stack = append(stack, ']')
			s.offset++
		case '}', ']':
			if s.content[s.offset] != stack[len(stack)-1] {
				return fmt.Errorf("invalid json: mismatched container")
			}
			stack = stack[:len(stack)-1]
			s.offset++
		default:
			s.offset++
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("invalid json: unterminated value")
	}
	return nil
}

func (s *jsonScanner) readString() (string, error) {
	start := s.offset
	s.offset++
	for s.offset < len(s.content) {
		switch s.content[s.offset] {
		case '\\':
			s.offset += 2
		case '"':
			s.offset++
			var value string
			if err := json.Unmarshal(s.content[start:s.offset], &value); err != nil {
				return "", err
			}
			return value, nil
		default:
			s.offset++
		}
	}
	return "", fmt.Errorf("invalid json: unterminated string")
}

func (s *jsonScanner) skipWhitespace() {
	for s.offset < len(s.content) {
		switch s.content[s.offset] {
		case ' ', '\n', '\r', '\t':
			s.offset++
		default:
			return
		}
	}
}

func (s *jsonScanner) take(char byte) bool {
	if s.offset < len(s.content) && s.content[s.offset] == char {
		s.offset++
		return true
	}
	return false
}

func isJSONDelimiter(char byte) bool {
	switch char {
	case ' ', '\n', '\r', '\t', ',', ']', '}':
		return true
	default:
		return false
	}
}

// jsonPayloadMarker prefixes plaintext containing the original JSON value
// token, so decryption can restore both its type and string spelling.
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

func decodeJSONPayload(plain []byte) (any, error) {
	rest, ok := strings.CutPrefix(string(plain), jsonPayloadMarker)
	if !ok {
		return string(plain), nil
	}
	return decodeJSON([]byte(rest))
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
		encrypted, err := envelope.Check(v)
		if err != nil {
			return nil, err
		}
		if encrypted {
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
