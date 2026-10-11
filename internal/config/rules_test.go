package config

import (
	"os"
	"strings"
	"testing"
)

func TestRuleValidation(t *testing.T) {
	key := newKey(t)
	for _, tc := range []struct {
		name, format, pattern, wantError string
	}{
		{"full", "full", `.*\.secret$`, ""},
		{"env", "env", `.*\.env$`, ""},
		{"json", "json", `.*\.json$`, ""},
		{"yaml", "yaml", `.*\.ya?ml$`, ""},
		{"unknown type", "ful", `.*`, "unsupported format type: ful"},
		{"missing type", "", `.*`, "unsupported format type:"},
		{"invalid regex", "full", `[`, "invalid path_regex"},
		{"empty regex matches all", "full", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Recipients: []Recipient{{Name: "me", Key: key}},
				Rules:      []Rule{{Type: tc.format, PathRegex: tc.pattern}},
			}
			err := cfg.Validate()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || !strings.Contains(err.Error(), "rule 1") {
					t.Fatalf("Validate error = %v, want %q with rule index", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Rules[0].pathPattern == nil {
				t.Fatal("pattern not compiled")
			}
		})
	}
}

func TestFindRuleCompiledPatterns(t *testing.T) {
	cfg := &Config{
		Recipients: []Recipient{{Name: "me", Key: newKey(t)}},
		Rules: []Rule{
			{Type: "json", PathRegex: `^app\.json$`},
			{Type: "full", PathRegex: `.*`},
		},
	}
	if _, err := cfg.FindRule("app.json"); err == nil {
		t.Fatal("unvalidated rules must report an error")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pattern := cfg.Rules[0].pathPattern
	for _, tc := range []struct{ path, format string }{
		{"app.json", "json"},
		{"other.secret", "full"},
		{"app.json", "json"},
	} {
		rule, err := cfg.FindRule(tc.path)
		if err != nil || rule == nil || rule.Type != tc.format {
			t.Fatalf("FindRule(%q) = %+v, %v", tc.path, rule, err)
		}
		if cfg.Rules[0].pathPattern != pattern {
			t.Fatal("pattern was recompiled during matching")
		}
	}
	cfg.Rules = cfg.Rules[:1]
	if rule, err := cfg.FindRule("unmatched.yaml"); err != nil || rule != nil {
		t.Fatalf("unmatched rule = %+v, %v", rule, err)
	}
	cfg.Rules[0].PathRegex = `[`
	if _, err := cfg.FindRule("app.json"); err == nil {
		t.Fatal("changed patterns require revalidation")
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid changed pattern accepted")
	}
	if cfg.Rules[0].pathPattern != nil {
		t.Fatal("invalid pattern retained its old compiled value")
	}
}

func TestSaveRejectsInvalidRulesBeforeWriting(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := Init([]Recipient{{Name: "me", Key: newKey(t)}}, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ConfigFileName)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Rules[0].Type = "ful"
	if err := cfg.Save(); err == nil {
		t.Fatal("invalid rules saved successfully")
	}
	after, err := os.ReadFile(ConfigFileName)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("invalid Save modified the config")
	}
}
