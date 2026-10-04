package keys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "sub", "ci.key")

	res, err := Generate(Options{Path: out, Name: "ci-deploy"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	if !strings.Contains(res.Content, "# Name: ci-deploy") || !strings.Contains(res.Content, res.PublicKey) {
		t.Errorf("unexpected content: %q", res.Content)
	}

	if _, err := Generate(Options{Path: out}); err == nil {
		t.Error("expected error overwriting without force")
	}
	if _, err := Generate(Options{Path: out, Force: true}); err != nil {
		t.Errorf("force overwrite failed: %v", err)
	}
}

func TestGenerateStdout(t *testing.T) {
	res, err := Generate(Options{Stdout: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Path != "" {
		t.Errorf("stdout mode wrote a file: %s", res.Path)
	}
	if _, err := Generate(Options{Stdout: true, Path: "x"}); err == nil {
		t.Error("expected error combining stdout and path")
	}
}

func TestReadPrivateKeyPrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)

	def, err := Generate(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defPriv, _ := parsePrivateKey(def.Content)

	got, err := ReadPrivateKey()
	if err != nil || got != defPriv {
		t.Fatalf("default: got %q, %v", got, err)
	}

	fileKey, err := Generate(Options{Path: filepath.Join(dir, "f.key")})
	if err != nil {
		t.Fatal(err)
	}
	filePriv, _ := parsePrivateKey(fileKey.Content)
	t.Setenv(EnvKeyFile, fileKey.Path)
	if got, _ := ReadPrivateKey(); got != filePriv {
		t.Errorf("%s: got %q, want %q", EnvKeyFile, got, filePriv)
	}

	t.Setenv(EnvKey, "abcd")
	if got, _ := ReadPrivateKey(); got != "abcd" {
		t.Errorf("%s: got %q", EnvKey, got)
	}

	t.Setenv(EnvKey, def.Content)
	if got, _ := ReadPrivateKey(); got != defPriv {
		t.Errorf("%s with file content: got %q", EnvKey, got)
	}
}
