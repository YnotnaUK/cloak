package engine

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ynotnauk/cloak/internal/config"
	"github.com/ynotnauk/cloak/internal/crypto"
)

func setup(t *testing.T, name, content string) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(priv.PublicKey().Bytes())
	SetKeyLoader(func() (string, error) { return hex.EncodeToString(priv.Bytes()), nil })

	if err := config.Init([]config.Recipient{{Name: "me", Key: pub}}, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	if err := Process(false, []string{name}); err != nil {
		t.Fatal(err)
	}
}

func replaceInFile(old, new string) func(string) error {
	return func(path string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(path, []byte(strings.ReplaceAll(string(b), old, new)), 0600)
	}
}

func tempFilesLeft(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(os.Getenv("XDG_RUNTIME_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestEditChange(t *testing.T) {
	setup(t, "app.yaml", "name: web\npassword: old\n")

	var seenMode os.FileMode
	res, err := Edit("app.yaml", EditOptions{Run: func(p string) error {
		info, _ := os.Stat(p)
		seenMode = info.Mode().Perm()
		b, _ := os.ReadFile(p)
		if !strings.Contains(string(b), "password: old") {
			t.Errorf("editor did not see plaintext: %q", b)
		}
		return replaceInFile("old", "new")(p)
	}})
	if err != nil || !res.Changed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if seenMode != 0600 {
		t.Errorf("temp file mode = %v", seenMode)
	}
	if n := tempFilesLeft(t); n != 0 {
		t.Errorf("%d temp entries left behind", n)
	}

	onDisk, _ := os.ReadFile("app.yaml")
	if strings.Contains(string(onDisk), "new") || !strings.Contains(string(onDisk), crypto.Prefix) {
		t.Errorf("file not re-encrypted: %s", onDisk)
	}
	info, _ := os.Stat("app.yaml")
	if info.Mode().Perm() != 0640 {
		t.Errorf("file mode changed to %v", info.Mode().Perm())
	}
	got, err := ExtractValue("app.yaml", "password")
	if err != nil || string(got) != "new" {
		t.Errorf("extract = %q, %v", got, err)
	}
}

func TestEditNewSecretKeyIsEncrypted(t *testing.T) {
	setup(t, "app.yaml", "name: web\n")
	_, err := Edit("app.yaml", EditOptions{Run: replaceInFile("name: web", "name: web\ntoken: abc")})
	if err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile("app.yaml")
	if strings.Contains(string(onDisk), "abc") {
		t.Errorf("new token left in plaintext: %s", onDisk)
	}
}

func TestEditUnchangedLeavesFileAlone(t *testing.T) {
	setup(t, "app.yaml", "password: pw\n")
	before, _ := os.ReadFile("app.yaml")

	res, err := Edit("app.yaml", EditOptions{Run: func(string) error { return nil }})
	if err != nil || res.Changed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	after, _ := os.ReadFile("app.yaml")
	if string(before) != string(after) {
		t.Error("file was rewritten despite no changes")
	}
}

func TestEditInvalidContent(t *testing.T) {
	setup(t, "app.json", `{"password":"pw"}`)
	before, _ := os.ReadFile("app.json")
	breakJSON := replaceInFile(`"pw"`, `"pw`)

	t.Run("declined keeps edits and original", func(t *testing.T) {
		res, err := Edit("app.json", EditOptions{Run: breakJSON})
		if err == nil || res.KeptPath == "" {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		after, _ := os.ReadFile("app.json")
		if string(before) != string(after) {
			t.Error("original overwritten with invalid content")
		}
		if _, err := os.Stat(res.KeptPath); err != nil {
			t.Errorf("kept file missing: %v", err)
		}
	})

	t.Run("retry reopens editor", func(t *testing.T) {
		calls := 0
		res, err := Edit("app.json", EditOptions{
			Run: func(p string) error {
				calls++
				if calls == 1 {
					return breakJSON(p)
				}
				return replaceInFile(`"pw`, `"pw2"`)(p)
			},
			Retry: func(error) bool { return true },
		})
		if err != nil || !res.Changed || calls != 2 {
			t.Fatalf("res=%+v err=%v calls=%d", res, err, calls)
		}
	})
}

func TestEditEditorFailure(t *testing.T) {
	setup(t, "app.yaml", "password: pw\n")
	before, _ := os.ReadFile("app.yaml")

	_, err := Edit("app.yaml", EditOptions{Run: func(string) error { return errors.New("boom") }})
	if err == nil {
		t.Fatal("expected error")
	}
	after, _ := os.ReadFile("app.yaml")
	if string(before) != string(after) {
		t.Error("file changed after editor failure")
	}
	if n := tempFilesLeft(t); n != 0 {
		t.Errorf("%d temp entries left behind", n)
	}
}

func TestEditRejectsExcludedAndOutsideFiles(t *testing.T) {
	setup(t, "app.yaml", "a: b\n")
	for _, p := range []string{config.ConfigFileName, "../x.yaml", "missing.yaml"} {
		if _, err := Edit(p, EditOptions{Run: func(string) error { return nil }}); err == nil {
			t.Errorf("Edit(%q) should fail", p)
		}
	}
}

func TestEditorCommand(t *testing.T) {
	tests := []struct {
		visual, editor string
		want           []string
	}{
		{"", "", []string{"vi"}},
		{"", "nano", []string{"nano"}},
		{"code --wait", "nano", []string{"code", "--wait"}},
		{"  ", "emacs -nw", []string{"emacs", "-nw"}},
	}
	for _, tc := range tests {
		t.Setenv("VISUAL", tc.visual)
		t.Setenv("EDITOR", tc.editor)
		got := editorCommand()
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("VISUAL=%q EDITOR=%q: got %v, want %v", tc.visual, tc.editor, got, tc.want)
		}
	}
}
