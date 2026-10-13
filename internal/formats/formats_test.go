package formats_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ynotnauk/cloak/internal/envelope"
	"github.com/ynotnauk/cloak/internal/formats"
	"gopkg.in/yaml.v3"
)

// mockEncrypt produces a structurally valid envelope whose "ciphertext" is the
// plaintext followed by a dummy tag, so formatter tests exercise real validation.
func mockEncrypt(b []byte) (string, error) {
	env := &envelope.Envelope{
		IV:   make([]byte, envelope.IVSize),
		Data: append(append([]byte{}, b...), make([]byte, envelope.TagSize)...),
		Wraps: []envelope.Wrap{{
			EphemeralPub: make([]byte, envelope.PubKeySize),
			IV:           make([]byte, envelope.IVSize),
			Key:          make([]byte, envelope.WrappedSize),
		}},
	}
	return env.String(), nil
}

func mockDecrypt(s string) ([]byte, error) {
	env, err := envelope.Parse(s)
	if err != nil {
		return nil, err
	}
	return env.Data[:len(env.Data)-envelope.TagSize], nil
}

func mockEnv(plain string) string {
	s, _ := mockEncrypt([]byte(plain))
	return s
}

func yamlPayload(value string) string {
	return `{"tag":"!!str","style":0,"value":"` + value + `"}`
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

	if strings.Contains(string(enc), "secret123") || !strings.Contains(string(enc), "PASSWORD=CLOAK[v1,") {
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
		{"yaml nested encrypted", "yaml", "db:\n  password: " + mockEnv(yamlPayload("s3cret")) + "\n", "db.password", "s3cret", false},
		{"yaml plaintext", "yaml", "app: web\n", "app", "web", false},
		{"yaml sequence", "yaml", "servers:\n  - token: " + mockEnv(yamlPayload("abc")) + "\n", "servers.0.token", "abc", false},
		{"yaml missing", "yaml", "app: web\n", "nope", "", true},
		{"yaml map is not scalar", "yaml", "db:\n  a: 1\n", "db", "", true},
		{"json nested", "json", `{"db":{"password":"` + mockEnv("pw") + `"}}`, "db.password", "pw", false},
		{"json number", "json", `{"replicas":3}`, "replicas", "3", false},
		{"json array", "json", `{"a":["x","y"]}`, "a.1", "y", false},
		{"json missing", "json", `{"a":1}`, "b", "", true},
		{"json object is not scalar", "json", `{"a":{"b":1}}`, "a", "", true},
		{"env encrypted", "env", "APP=web\nPASSWORD=" + mockEnv("pw") + "\n", "PASSWORD", "pw", false},
		{"env plaintext", "env", "APP=web\n", "APP", "web", false},
		{"env missing", "env", "APP=web\n", "NOPE", "", true},
		{"full unsupported", "full", mockEnv("x") + "\n", "any", "", true},
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
			input := []byte("password: " + ciphertext + "\n")
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
	input := []byte("password: " + ciphertext + "\n")
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
		return mockEncrypt(plain)
	}
	decryptFn := func(ciphertext string) ([]byte, error) {
		return mockDecrypt(ciphertext)
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
  "pass\u0077ord" : "` + mockEnv("\x00json:\"<secret &>\"") + `",
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
	input := []byte(`["` + mockEnv("plain") + `"]`)
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

func TestPrefixShapedValuesAreRejectedNotSkipped(t *testing.T) {
	bad := []string{
		"CLOAK[v1,iv:AAAA]",
		"CLOAK[v1,iv:",
		"CLOAK[v2,iv:x,data:y,wrap:a.b.c]",
		"CLOAK:v1:old",
		"CLOAK:YAML:v1:old",
	}
	cases := map[string]func(v string) string{
		"yaml": func(v string) string { return "password: '" + v + "'\n" },
		"json": func(v string) string { return `{"password":"` + v + `"}` },
		"env":  func(v string) string { return "password=" + v + "\n" },
		"full": func(v string) string { return v + "\n" },
	}
	failEncrypt := func([]byte) (string, error) {
		t.Fatal("encryptor must not be reached for a reserved-prefix value")
		return "", nil
	}
	for format, build := range cases {
		f, err := formats.Get(format)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range bad {
			in := []byte(build(v))
			if _, err := f.Encrypt(in, []string{"password"}, failEncrypt); err == nil {
				t.Errorf("%s encrypt %q: expected error", format, v)
			}
			if _, err := f.Decrypt(in, mockDecrypt); err == nil {
				t.Errorf("%s decrypt %q: expected error", format, v)
			}
		}
	}
}

func TestValidEnvelopesAreIdempotentOnEncrypt(t *testing.T) {
	good := mockEnv(yamlPayload("x"))
	cases := map[string]string{
		"yaml": "password: " + good + "\n",
		"json": `{"password":"` + good + `"}`,
		"env":  "pass" + "word=" + good + "\n",
		"full": good + "\n",
	}

	for format, in := range cases {
		f, err := formats.Get(format)
		if err != nil {
			t.Fatal(err)
		}
		out, err := f.Encrypt([]byte(in), []string{"password"}, func([]byte) (string, error) {
			t.Fatal("already-encrypted value was re-encrypted")
			return "", nil
		})
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if format != "yaml" && string(out) != in {
			t.Errorf("%s: output changed: %q", format, out)
		}
	}
}

func TestHasEncryptedOnlyChecksConfiguredFields(t *testing.T) {
	ciphertext := mockEnv(yamlPayload("secret"))
	tests := []struct {
		format string
		input  string
		want   bool
		err    bool
	}{
		{"yaml", "# CLOAK[comment]\nnote: CLOAK[v1,invalid]\n", false, false},
		{"yaml", "password: " + ciphertext + "\nnote: CLOAK[v1,invalid]\n", true, false},
		{"yaml", "password: CLOAK[v1,invalid]\n", false, true},
		{"json", `{"note":"CLOAK[v1,invalid]"}`, false, false},
		{"json", `{"password":"` + ciphertext + `","note":"CLOAK[v1,invalid]"}`, true, false},
		{"json", `{"password":"CLOAK[v1,invalid]"}`, false, true},
		{"env", "PASS" + "WORD=" + ciphertext + "\nnote=CLOAK[v1,invalid]\n", true, false},
		{"env", "note=CLOAK[v1,invalid]\n", false, false},
		{"env", "PASS" + "WORD=CLOAK[v1,invalid]\n", false, true},
		{"full", ciphertext + "\n", true, false},
		{"full", "CLOAK[v1,invalid]\n", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.format+"/"+tc.input, func(t *testing.T) {
			got, err := formats.HasEncrypted(tc.format, []byte(tc.input), []string{"password", "PASSWORD"})
			if got != tc.want || (err != nil) != tc.err {
				t.Fatalf("HasEncrypted = (%v, %v), want (%v, err=%v)", got, err, tc.want, tc.err)
			}
		})
	}
}
