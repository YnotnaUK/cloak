package formats

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

type EnvFormatter struct{}

func (e *EnvFormatter) Encrypt(content []byte, targetKeys []string, encryptFn func([]byte) (string, error)) ([]byte, error) {
	keySet := make(map[string]bool, len(targetKeys))
	for _, k := range targetKeys {
		keySet[k] = true
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
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
			trimmedVal := strings.TrimSpace(v)
			if strings.HasPrefix(trimmedVal, "CLOAK:v1:") {
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
	scanner := bufio.NewScanner(bytes.NewReader(content))
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

		// Attempt decrypt if it looks encrypted
		if strings.HasPrefix(v, "CLOAK:v1:") {
			decVal, err := decryptFn(v)
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
