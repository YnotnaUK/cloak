package formats

import (
	"bufio"
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

	scanner := newEnvScanner(content)
	var out bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Preserve comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.Contains(line, "=") {
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		k := strings.TrimSpace(parts[0])
		v := parts[1]

		if keySet[k] {
			encrypted, err := envelope.Check(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("key %s: %w", k, err)
			}
			if encrypted {
				out.WriteString(line)
				out.WriteByte('\n')
				continue
			}

			encVal, err := encryptFn([]byte(v))
			if err != nil {
				return nil, fmt.Errorf("failed encrypting key %s: %w", k, err)
			}
			out.WriteString(k)
			out.WriteByte('=')
			out.WriteString(encVal)
			out.WriteByte('\n')
		} else {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}

	return out.Bytes(), scanner.Err()
}

func (e *EnvFormatter) Decrypt(content []byte, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	scanner := newEnvScanner(content)
	var out bytes.Buffer

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.Contains(line, "=") {
			out.WriteString(line)
			out.WriteByte('\n')
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		k := strings.TrimSpace(parts[0])
		v := parts[1]

		encrypted, err := envelope.Check(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		if encrypted {
			decVal, err := decryptFn(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("failed decrypting key %s: %w", k, err)
			}
			out.WriteString(k)
			out.WriteByte('=')
			out.Write(decVal)
			out.WriteByte('\n')
		} else {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}

	return out.Bytes(), scanner.Err()
}

func (e *EnvFormatter) Extract(content []byte, path string, decryptFn func(string) ([]byte, error)) ([]byte, error) {
	scanner := newEnvScanner(content)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if strings.TrimSpace(k) != path {
			continue
		}
		encrypted, err := envelope.Check(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		if encrypted {
			return decryptFn(strings.TrimSpace(v))
		}
		return []byte(v), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, notFound(path)
}

func newEnvScanner(content []byte) *bufio.Scanner {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	const defaultBufferSize = 64 * 1024
	maxTokenSize := max(defaultBufferSize, len(content)+1)
	scanner.Buffer(make([]byte, defaultBufferSize), maxTokenSize)
	return scanner
}
