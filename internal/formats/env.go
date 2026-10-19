package formats

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ynotnauk/cloak/internal/envelope"
)

type EnvFormatter struct{}

func (e *EnvFormatter) Encrypt(content []byte, targetKeys []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	keySet := make(map[string]bool, len(targetKeys))
	for _, k := range targetKeys {
		keySet[k] = true
	}

	var out bytes.Buffer

	for _, line := range splitEnvLines(content) {
		if isEnvCommentOrEmpty(line.text) {
			writeEnvLine(&out, line, line.text)
			continue
		}

		assignment, ok := parseEnvAssignment(line.text)
		if !ok || !keySet[assignment.key] {
			writeEnvLine(&out, line, line.text)
			continue
		}
		value := line.text[assignment.valueStart:assignment.valueEnd]
		encrypted, err := envelope.Check(string(value))
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", assignment.key, err)
		}
		if encrypted {
			writeEnvLine(&out, line, line.text)
			continue
		}

		encVal, err := encryptFn(value)
		if err != nil {
			return nil, fmt.Errorf("failed encrypting key %s: %w", assignment.key, err)
		}
		updated := make([]byte, 0, len(line.text)+len(encVal)-len(value))
		updated = append(updated, line.text[:assignment.valueStart]...)
		updated = append(updated, encVal...)
		updated = append(updated, line.text[assignment.valueEnd:]...)
		writeEnvLine(&out, line, updated)
	}

	return out.Bytes(), nil
}

func (e *EnvFormatter) Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	var out bytes.Buffer

	for _, line := range splitEnvLines(content) {
		if isEnvCommentOrEmpty(line.text) {
			writeEnvLine(&out, line, line.text)
			continue
		}

		assignment, ok := parseEnvAssignment(line.text)
		if !ok {
			writeEnvLine(&out, line, line.text)
			continue
		}
		value := line.text[assignment.valueStart:assignment.valueEnd]
		encrypted, err := envelope.Check(string(value))
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", assignment.key, err)
		}
		if !encrypted {
			writeEnvLine(&out, line, line.text)
			continue
		}

		decVal, err := decryptFn(string(value))
		if err != nil {
			return nil, fmt.Errorf("failed decrypting key %s: %w", assignment.key, err)
		}
		updated := make([]byte, 0, len(line.text)+len(decVal)-len(value))
		updated = append(updated, line.text[:assignment.valueStart]...)
		updated = append(updated, decVal...)
		updated = append(updated, line.text[assignment.valueEnd:]...)
		writeEnvLine(&out, line, updated)
	}

	return out.Bytes(), nil
}

func (e *EnvFormatter) Extract(content []byte, path string, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	for _, line := range splitEnvLines(content) {
		if strings.TrimSpace(string(line.text)) == "" || bytes.HasPrefix(bytes.TrimSpace(line.text), []byte("#")) {
			continue
		}
		assignment, ok := parseEnvAssignment(line.text)
		if !ok || assignment.key != path {
			continue
		}

		value := line.text[assignment.valueStart:assignment.valueEnd]
		encrypted, err := envelope.Check(string(value))
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", assignment.key, err)
		}
		if !encrypted {
			return append([]byte(nil), value...), nil
		}
		return decryptFn(string(value))
	}
	return nil, notFound(path)
}

type envLine struct {
	text   []byte
	ending []byte
}

type envAssignment struct {
	key        string
	valueStart int
	valueEnd   int
}

func splitEnvLines(content []byte) []envLine {
	var lines []envLine
	for len(content) > 0 {
		newline := bytes.IndexByte(content, '\n')
		if newline < 0 {
			lines = append(lines, envLine{text: content})
			break
		}
		text := content[:newline]
		ending := content[newline : newline+1]
		if len(text) > 0 && text[len(text)-1] == '\r' {
			text = text[:len(text)-1]
			ending = content[newline-1 : newline+1]
		}
		lines = append(lines, envLine{text: text, ending: ending})
		content = content[newline+1:]
	}
	return lines
}

func parseEnvAssignment(line []byte) (envAssignment, bool) {
	equals := bytes.IndexByte(line, '=')
	if equals < 0 {
		return envAssignment{}, false
	}

	key := strings.TrimSpace(string(line[:equals]))
	if len(key) > len("export") && key[:len("export")] == "export" && (key[len("export")] == ' ' || key[len("export")] == '\t') {
		key = strings.TrimSpace(key[len("export"):])
	}
	if key == "" {
		return envAssignment{}, false
	}

	valueStart := equals + 1
	for valueStart < len(line) && (line[valueStart] == ' ' || line[valueStart] == '\t') {
		valueStart++
	}
	valueEnd := len(line)
	for valueEnd > valueStart && (line[valueEnd-1] == ' ' || line[valueEnd-1] == '\t') {
		valueEnd--
	}

	return envAssignment{key: key, valueStart: valueStart, valueEnd: valueEnd}, true
}

func writeEnvLine(out *bytes.Buffer, line envLine, text []byte) {
	out.Write(text)
	out.Write(line.ending)
}

func isEnvCommentOrEmpty(line []byte) bool {
	trimmed := bytes.TrimSpace(line)
	return len(trimmed) == 0 || trimmed[0] == '#'
}
