package formats_test

import (
	"strings"
	"testing"

	"github.com/ynotnauk/cloak/internal/crypto"
	"github.com/ynotnauk/cloak/internal/formats"
)

// Mock crypto functions using current crypto.Prefix
func mockEncrypt(b []byte) (string, error) {
	return crypto.Prefix + "mock:" + string(b), nil
}

func mockDecrypt(s string) ([]byte, error) {
	return []byte(strings.TrimPrefix(s, crypto.Prefix+"mock:")), nil
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

	if !strings.Contains(string(enc), "PASSWORD="+crypto.Prefix+"mock:secret123") {
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

func TestExtract(t *testing.T) {
	tests := []struct {
		name, format, input, path, want string
		wantErr                         bool
	}{
		{"yaml nested encrypted", "yaml", "db:\n  password: " + crypto.Prefix + "mock:s3cret\n", "db.password", "s3cret", false},
		{"yaml plaintext", "yaml", "app: web\n", "app", "web", false},
		{"yaml sequence", "yaml", "servers:\n  - token: " + crypto.Prefix + "mock:abc\n", "servers.0.token", "abc", false},
		{"yaml missing", "yaml", "app: web\n", "nope", "", true},
		{"yaml map is not scalar", "yaml", "db:\n  a: 1\n", "db", "", true},
		{"json nested", "json", `{"db":{"password":"` + crypto.Prefix + `mock:pw"}}`, "db.password", "pw", false},
		{"json number", "json", `{"replicas":3}`, "replicas", "3", false},
		{"json array", "json", `{"a":["x","y"]}`, "a.1", "y", false},
		{"json missing", "json", `{"a":1}`, "b", "", true},
		{"json object is not scalar", "json", `{"a":{"b":1}}`, "a", "", true},
		{"env encrypted", "env", "APP=web\nPASSWORD=" + crypto.Prefix + "mock:pw\n", "PASSWORD", "pw", false},
		{"env plaintext", "env", "APP=web\n", "APP", "web", false},
		{"env missing", "env", "APP=web\n", "NOPE", "", true},
		{"full unsupported", "full", crypto.Prefix + "mock:x\n", "any", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := formats.Get(tc.format)
			if err != nil {
				t.Fatal(err)
			}
			got, err := f.Extract([]byte(tc.input), tc.path, mockDecrypt)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestYamlMultiDocument(t *testing.T) {
	input := []byte("a: 1\npassword: x\n---\nb: 2\npassword: y\n")
	f, err := formats.Get("yaml")
	if err != nil {
		t.Fatal(err)
	}

	enc, err := f.Encrypt(input, []string{"password"}, mockEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	out := string(enc)
	if strings.Contains(out, "password: x") || strings.Contains(out, "password: y") {
		t.Fatalf("plaintext left in output:\n%s", out)
	}
	if !strings.Contains(out, "b: 2") || strings.Count(out, "---") != 1 {
		t.Fatalf("second document lost:\n%s", out)
	}

	dec, err := f.Decrypt(enc, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != string(input) {
		t.Fatalf("round trip mismatch:\n%s", dec)
	}
}

func TestJsonArrays(t *testing.T) {
	f, err := formats.Get("json")
	if err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{
		`{"servers":[{"password":"plain1"},[{"password":"plain2"}]]}`,
		`[{"password":"plain1"},{"nested":{"password":"plain2"}}]`,
	} {
		enc, err := f.Encrypt([]byte(input), []string{"password"}, mockEncrypt)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(enc), `"plain`) {
			t.Fatalf("plaintext left in output:\n%s", enc)
		}
		dec, err := f.Decrypt(enc, mockDecrypt)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(dec), "plain1") || !strings.Contains(string(dec), "plain2") {
			t.Fatalf("decrypt failed:\n%s", dec)
		}
	}
}
