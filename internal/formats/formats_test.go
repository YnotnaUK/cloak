package formats_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ynotnauk/cloak/internal/crypto"
	"github.com/ynotnauk/cloak/internal/formats"
	"gopkg.in/yaml.v3"
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

func TestYAMLFormatterPreservesScalarTypes(t *testing.T) {
	f, err := formats.Get("yaml")
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("password: 12345\ntoken: true\nsecret: null\nrate: 1.25\napp: hello\nquoted: 'value' # preserved comment\n")
	keys := []string{"password", "token", "secret", "rate", "app", "quoted"}

	encrypted, err := f.Encrypt(input, keys, mockEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := f.Decrypt(encrypted, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}

	var document yaml.Node
	if err := yaml.Unmarshal(decrypted, &document); err != nil {
		t.Fatalf("decrypted YAML %q: %v", decrypted, err)
	}
	got := make(map[string]*yaml.Node)
	for i := 0; i < len(document.Content[0].Content); i += 2 {
		got[document.Content[0].Content[i].Value] = document.Content[0].Content[i+1]
	}
	for key, want := range map[string]struct {
		tag   string
		value string
		style yaml.Style
	}{
		"password": {tag: "!!int", value: "12345"},
		"token":    {tag: "!!bool", value: "true"},
		"secret":   {tag: "!!null", value: "null"},
		"rate":     {tag: "!!float", value: "1.25"},
		"app":      {tag: "!!str", value: "hello"},
		"quoted":   {tag: "!!str", value: "value", style: yaml.SingleQuotedStyle},
	} {
		node := got[key]
		if node == nil {
			t.Errorf("%s is missing", key)
			continue
		}
		if node.Tag != want.tag || node.Value != want.value || node.Style != want.style {
			t.Errorf("%s = tag %q, value %q, style %d; want tag %q, value %q, style %d", key, node.Tag, node.Value, node.Style, want.tag, want.value, want.style)
		}
	}

	extracted, err := f.Extract(encrypted, "password", mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if string(extracted) != "12345" {
		t.Fatalf("extracted typed scalar = %q, want %q", extracted, "12345")
	}
}

func TestYAMLDecryptSupportsLegacyCiphertext(t *testing.T) {
	f, err := formats.Get("yaml")
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("password: " + crypto.Prefix + "mock:12345\n")
	decrypted, err := f.Decrypt(input, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(decrypted, &document); err != nil {
		t.Fatal(err)
	}
	value := document.Content[0].Content[1]
	if value.Tag != "!!str" || value.Value != "12345" {
		t.Fatalf("legacy scalar = tag %q, value %q; want string %q", value.Tag, value.Value, "12345")
	}
}

func TestYAMLDecryptPreservesLegacyPayloadPrefixAsString(t *testing.T) {
	f, err := formats.Get("yaml")
	if err != nil {
		t.Fatal(err)
	}
	legacyValues := []string{
		"\x00cloak:yaml:v1:not-json",
		"\x00cloak:yaml:v1:{\"tag\":\"!!int\",\"style\":0,\"value\":\"123\"}",
	}
	for i, value := range legacyValues {
		t.Run(fmt.Sprintf("legacy-%d", i), func(t *testing.T) {
			ciphertext, err := mockEncrypt([]byte(value))
			if err != nil {
				t.Fatal(err)
			}
			input, err := yaml.Marshal(map[string]string{"password": ciphertext})
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := f.Decrypt(input, mockDecrypt)
			if err != nil {
				t.Fatal(err)
			}
			var document yaml.Node
			if err := yaml.Unmarshal(decrypted, &document); err != nil {
				t.Fatal(err)
			}
			scalar := document.Content[0].Content[1]
			if scalar.Tag != "!!str" || scalar.Value != value {
				t.Fatalf("legacy scalar = tag %q, value %q; want string %q", scalar.Tag, scalar.Value, value)
			}
			extracted, err := f.Extract(input, "password", mockDecrypt)
			if err != nil {
				t.Fatal(err)
			}
			if string(extracted) != value {
				t.Fatalf("legacy extracted value = %q, want %q", extracted, value)
			}
		})
	}
}

func TestYAMLFormatterTreatsOuterMarkerAloneAsPlaintext(t *testing.T) {
	f, err := formats.Get("yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"CLOAK:YAML:v1:", "CLOAK:YAML:v1:literal"} {
		t.Run(value, func(t *testing.T) {
			input, err := yaml.Marshal(map[string]string{"password": value})
			if err != nil {
				t.Fatal(err)
			}
			unexpectedDecrypt := func(string) ([]byte, error) {
				t.Fatal("decryptor called for plaintext")
				return nil, nil
			}
			plain, err := f.Decrypt(input, unexpectedDecrypt)
			if err != nil {
				t.Fatal(err)
			}
			if string(plain) != string(input) {
				t.Fatalf("plaintext changed: got %q, want %q", plain, input)
			}
			extracted, err := f.Extract(input, "password", unexpectedDecrypt)
			if err != nil {
				t.Fatal(err)
			}
			if string(extracted) != value {
				t.Fatalf("plaintext extraction = %q, want %q", extracted, value)
			}
			encryptCalls := 0
			encrypted, err := f.Encrypt(input, []string{"password"}, func(payload []byte) (string, error) {
				encryptCalls++
				return crypto.Prefix + "mock:" + base64.RawStdEncoding.EncodeToString(payload), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if encryptCalls != 1 || strings.Contains(string(encrypted), "literal") {
				t.Fatalf("plaintext was not encrypted: calls=%d, output=%q", encryptCalls, encrypted)
			}
			decrypted, err := f.Decrypt(encrypted, func(ciphertext string) ([]byte, error) {
				return base64.RawStdEncoding.DecodeString(strings.TrimPrefix(ciphertext, crypto.Prefix+"mock:"))
			})
			if err != nil {
				t.Fatal(err)
			}
			if string(decrypted) != string(input) {
				t.Fatalf("round trip = %q, want %q", decrypted, input)
			}
		})
	}
}

func TestYAMLDecryptRejectsMalformedTypedPayloads(t *testing.T) {
	f, err := formats.Get("yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, payload string
	}{
		{name: "missing value", payload: `{"tag":"!!str","style":0}`},
		{name: "missing style", payload: `{"tag":"!!str","value":"x"}`},
		{name: "wrong tag type", payload: `{"tag":1,"style":0,"value":"x"}`},
		{name: "wrong style type", payload: `{"tag":"!!str","style":"plain","value":"x"}`},
		{name: "wrong value type", payload: `{"tag":"!!str","style":0,"value":false}`},
		{name: "unknown field", payload: `{"tag":"!!str","style":0,"value":"x","extra":true}`},
		{name: "invalid style", payload: `{"tag":"!!str","style":128,"value":"x"}`},
		{name: "trailing JSON", payload: `{"tag":"!!str","style":0,"value":"x"}{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := mockEncrypt([]byte(tc.payload))
			if err != nil {
				t.Fatal(err)
			}
			input := []byte("password: " + "CLOAK:YAML:v1:" + ciphertext + "\n")
			if _, err := f.Decrypt(input, mockDecrypt); err == nil {
				t.Fatal("expected malformed payload to fail decryption")
			}
			if _, err := f.Extract(input, "password", mockDecrypt); err == nil {
				t.Fatal("expected malformed payload to fail extraction")
			}
		})
	}
}

func TestYAMLDecryptAcceptsEmptyTypedValueAndZeroStyle(t *testing.T) {
	f, err := formats.Get("yaml")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := mockEncrypt([]byte(`{"tag":"!!str","style":0,"value":""}`))
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("password: " + "CLOAK:YAML:v1:" + ciphertext + "\n")
	decrypted, err := f.Decrypt(input, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(decrypted, &document); err != nil {
		t.Fatal(err)
	}
	scalar := document.Content[0].Content[1]
	if scalar.Tag != "!!str" || scalar.Value != "" {
		t.Fatalf("decoded scalar = tag %q, value %q", scalar.Tag, scalar.Value)
	}
	extracted, err := f.Extract(input, "password", mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if len(extracted) != 0 {
		t.Fatalf("extracted empty scalar = %q, want empty value", extracted)
	}
}

func TestJsonArrays(t *testing.T) {
	f, err := formats.Get("json")
	if err != nil {
		t.Fatal(err)
	}
	encryptFn := func(plain []byte) (string, error) {
		return crypto.Prefix + "mock:" + base64.RawStdEncoding.EncodeToString(plain), nil
	}
	decryptFn := func(ciphertext string) ([]byte, error) {
		payload := strings.TrimPrefix(ciphertext, crypto.Prefix+"mock:")
		return base64.RawStdEncoding.DecodeString(payload)
	}

	for _, input := range []string{
		`{"servers":[{"password":"plain1"},[{"password":"plain2"}]]}`,
		`[{"password":"plain1"},{"nested":{"password":"plain2"}}]`,
	} {
		enc, err := f.Encrypt([]byte(input), []string{"password"}, encryptFn)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(enc), `"plain`) {
			t.Fatalf("plaintext left in output:\n%s", enc)
		}
		dec, err := f.Decrypt(enc, decryptFn)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(dec), "plain1") || !strings.Contains(string(dec), "plain2") {
			t.Fatalf("decrypt failed:\n%s", dec)
		}
	}
}

func TestJsonNonStringValues(t *testing.T) {
	f, err := formats.Get("json")
	if err != nil {
		t.Fatal(err)
	}

	input := `{"a":null,"b":["x","y"],"c":12345678901234567890,"d":true,"e":1.50,"f":"\u0000json:literal","g":"text","h":{"k":1},"i":[{"nested":[1,{"ok":true}]}]}`
	keys := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}

	enc, err := f.Encrypt([]byte(input), keys, mockEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := f.Decrypt(enc, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}

	var got, want map[string]any
	if err := json.Unmarshal(dec, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(input), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch:\n got %s\nwant %s", dec, input)
	}
	if !strings.Contains(string(dec), "12345678901234567890") || !strings.Contains(string(dec), "1.50") {
		t.Fatalf("number precision lost:\n%s", dec)
	}

	out, err := f.Extract(enc, "b", mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `["x","y"]` {
		t.Fatalf("unexpected extract: %s", out)
	}
}

func TestJSONFormatterPreservesStructureAroundEncryptedValues(t *testing.T) {
	f, err := formats.Get("json")
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("{\n  \"z\": \"<tag>&\",\n  \"pass\\u0077ord\" : \"<secret &>\",\n  \"a\": 12345678901234567890\n}\n")
	wantEncrypted := []byte(`{
  "z": "<tag>&",
  "pass\u0077ord" : "CLOAK:v1:mock:\u0000json:\"<secret &>\"",
  "a": 12345678901234567890
}
`)

	encrypted, err := f.Encrypt(input, []string{"password"}, mockEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	if string(encrypted) != string(wantEncrypted) {
		t.Fatalf("encryption changed JSON structure:\n got %s\nwant %s", encrypted, wantEncrypted)
	}

	decrypted, err := f.Decrypt(encrypted, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(input) {
		t.Fatalf("decryption changed JSON structure:\n got %s\nwant %s", decrypted, input)
	}
}

func TestJSONFormatterPreservesEscapedStringTokens(t *testing.T) {
	f, err := formats.Get("json")
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"password":"\u0073ecret","token":"a\/b","secret":"\u00e9"}`)

	encrypted, err := f.Encrypt(input, []string{"password", "token", "secret"}, mockEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := f.Decrypt(encrypted, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(input) {
		t.Fatalf("JSON string token spelling changed:\n got %s\nwant %s", decrypted, input)
	}
}

func TestJSONDecryptSupportsLegacyStringCiphertext(t *testing.T) {
	f, err := formats.Get("json")
	if err != nil {
		t.Fatal(err)
	}
	legacyCiphertext, err := mockEncrypt([]byte("legacy secret"))
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(`{"password":"` + legacyCiphertext + `"}`)
	want := []byte(`{"password":"legacy secret"}`)

	decrypted, err := f.Decrypt(input, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(want) {
		t.Fatalf("legacy ciphertext decryption = %s, want %s", decrypted, want)
	}
}

func TestJSONDecryptLeavesArrayElementStringsUntouched(t *testing.T) {
	input := []byte(`["` + crypto.Prefix + `mock:plain"]`)
	f, err := formats.Get("json")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := f.Decrypt(input, mockDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(input) {
		t.Fatalf("array element was unexpectedly decrypted: %s", decrypted)
	}
}
