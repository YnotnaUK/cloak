package engine

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/ynotnauk/cloak/internal/config"
	"gopkg.in/yaml.v3"
)

func TestInvalidRulesFailBeforeProcessing(t *testing.T) {
	for _, invalid := range []struct {
		name, format, pattern, wantError string
	}{
		{"unknown format", "ful", `.*\.secret$`, "unsupported format type: ful"},
		{"invalid regex", "full", `[`, "invalid path_regex"},
	} {
		for _, operation := range []struct {
			name string
			run  func() error
		}{
			{"encrypt explicit", func() error { return Process(false, []string{"app.yaml"}) }},
			{"encrypt walk", func() error { return Process(false, nil) }},
			{"decrypt explicit", func() error { return Process(true, []string{"app.yaml"}) }},
			{"decrypt walk", func() error { return Process(true, nil) }},
			{"rekey", Rekey},
			{"decrypt stdout", func() error { _, err := DecryptFile("app.yaml"); return err }},
			{"extract", func() error { _, err := ExtractValue("app.yaml", "password"); return err }},
			{"edit", func() error {
				_, err := Edit("app.yaml", EditOptions{Run: func(string) error {
					t.Error("editor must not run with invalid config")
					return nil
				}})
				return err
			}},
		} {
			t.Run(invalid.name+"/"+operation.name, func(t *testing.T) {
				setup(t, "app.yaml", "password: secret\n")
				plain := []byte("password: must-remain-unchanged\n")
				if err := os.WriteFile("other.yaml", plain, 0640); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile("app.yaml")
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := config.Load()
				if err != nil {
					t.Fatal(err)
				}
				// The invalid rule is last and matches no test file: validation must still fail.
				cfg.Rules = append(cfg.Rules, config.Rule{Type: invalid.format, PathRegex: invalid.pattern})
				data, err := yaml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(config.ConfigFileName, data, 0644); err != nil {
					t.Fatal(err)
				}
				keyCalled := false
				loader := cryptoPrivateKeyLoader
				t.Cleanup(func() { SetKeyLoader(loader) })
				SetKeyLoader(func() (string, error) {
					keyCalled = true
					return loader()
				})
				err = operation.run()
				if err == nil || !strings.Contains(err.Error(), invalid.wantError) {
					t.Fatalf("operation error = %v, want %q", err, invalid.wantError)
				}
				if keyCalled {
					t.Fatal("private key loaded before rule validation")
				}
				after, err := os.ReadFile("app.yaml")
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("file changed despite invalid config")
				}
				after, err = os.ReadFile("other.yaml")
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(plain, after) {
					t.Fatal("plaintext file changed despite invalid config")
				}
			})
		}
	}
}

func TestProcessFileRejectsUnknownFormat(t *testing.T) {
	err := processFile(&config.Config{}, "missing.secret", 0600, &config.Rule{Type: "ful"}, false, "")
	if err == nil || !strings.Contains(err.Error(), "missing.secret") || !strings.Contains(err.Error(), "unsupported format type: ful") {
		t.Fatalf("expected contextual format error before reading file, got %v", err)
	}
}
