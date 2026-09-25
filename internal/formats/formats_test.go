package formats_test

import (
	"strings"
	"testing"

	"github.com/ynotnauk/cloak/internal/formats"
)

// Mock crypto functions for testing formatters
func mockEncrypt(b []byte) (string, error) {
	return "CLOAK:v1:mock:" + string(b), nil
}

func mockDecrypt(s string) ([]byte, error) {
	return []byte(strings.TrimPrefix(s, "CLOAK:v1:mock:")), nil
}

func TestEnvFormatter(t *testing.T) {
	input := []byte("APP=web\nPASSWORD=secret123\nPORT=80\n")
	formatter, err := formats.Get("env")
	if err != nil {
		t.Fatal(err)
	}

	enc, err := formatter.Encrypt(input, []string{"PASSWORD"}, mockEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(enc), "PASSWORD=CLOAK:v1:mock:secret123") {
		t.Fatalf("expected encrypted PASSWORD, got:\n%s", string(enc))
	}

	dec, err := formatter.Decrypt(enc, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}

	if string(dec) != string(input) {
		t.Fatalf("expected %q, got %q", string(input), string(dec))
	}
}

func TestFullFormatter(t *testing.T) {
	input := []byte("plain text content")
	formatter, err := formats.Get("full")
	if err != nil {
		t.Fatal(err)
	}

	enc, err := formatter.Encrypt(input, nil, mockEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := formatter.Decrypt(enc, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}

	if string(dec) != string(input) {
		t.Fatalf("expected %q, got %q", string(input), string(dec))
	}
}
