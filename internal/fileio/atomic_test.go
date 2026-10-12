package fileio

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWritesHonourUmask(t *testing.T) {
	if os.Getenv("CLOAK_TEST_RESTRICTIVE_UMASK") != "1" {
		bash, err := exec.LookPath("bash")
		if err != nil {
			t.Skip("umask regression test requires bash")
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bash, "-c", `umask 077; exec "$@"`, "umask-test",
			executable, "-test.run=^TestAtomicWritesHonourUmask$", "-test.v")
		cmd.Env = append(os.Environ(), "CLOAK_TEST_RESTRICTIVE_UMASK=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("restricted umask test failed: %v\n%s", err, out)
		}
		return
	}

	dir := t.TempDir()
	for _, exclusive := range []bool{false, true} {
		name := "write"
		if exclusive {
			name = "create"
		}
		path := filepath.Join(dir, name)
		if err := writeFile(path, strings.NewReader("new"), 0644, exclusive); err != nil {
			t.Fatal(err)
		}
		checkFile(t, path, "new", 0600)
	}
	path := filepath.Join(dir, "existing")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	checkFile(t, path, "replacement", 0640)
	checkNoTemps(t, dir)
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type callbackReader struct {
	io.Reader
	before func()
}

func (r *callbackReader) Read(p []byte) (int, error) {
	if r.before != nil {
		r.before()
		r.before = nil
	}
	return r.Reader.Read(p)
}

func TestAtomicReplacement(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "regular", true: "symlink"}[symlink], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("original"), 0640); err != nil {
				t.Fatal(err)
			}
			backup := filepath.Join(dir, "old-inode")
			if err := os.Link(target, backup); err != nil {
				t.Fatal(err)
			}
			path := target
			if symlink {
				path = filepath.Join(dir, "link")
				if err := os.Symlink("target", path); err != nil {
					t.Fatal(err)
				}
			}
			if err := WriteFile(path, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			checkFile(t, target, "replacement", 0640)
			checkFile(t, backup, "original", 0640)
			if symlink {
				info, err := os.Lstat(path)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("symlink replaced: %v, %v", info, err)
				}
			}
			checkNoTemps(t, dir)
		})
	}
}

func TestFailedWritePreservesOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("disk full")
	reader := io.MultiReader(strings.NewReader("partial replacement"), errorReader{injected})
	if err := writeFile(path, reader, 0644, false); !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected failure", err)
	}
	checkFile(t, path, "original", 0600)
	checkNoTemps(t, dir)
}

func TestFailedCreationLeavesNoDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	injected := errors.New("interrupted write")
	reader := io.MultiReader(strings.NewReader("partial"), errorReader{injected})
	if err := writeFile(path, reader, 0644, true); !errors.Is(err, injected) {
		t.Fatalf("creation error = %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial config published: %v", err)
	}
	checkNoTemps(t, dir)
}

func TestExclusiveCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := CreateFile(path, []byte("first"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := CreateFile(path, []byte("second"), 0644); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive creation error = %v", err)
	}
	checkFile(t, path, "first", 0640)
	checkNoTemps(t, dir)
}

func TestExclusiveCreateRejectsRacingCreator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	reader := &callbackReader{Reader: strings.NewReader("ours"), before: func() {
		if err := os.WriteFile(path, []byte("racing creator"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	if err := writeFile(path, reader, 0644, true); !errors.Is(err, os.ErrExist) {
		t.Fatalf("racing creation error = %v", err)
	}
	checkFile(t, path, "racing creator", 0600)
	checkNoTemps(t, dir)
}

func TestRenameFailureCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "destination")
	reader := &callbackReader{Reader: strings.NewReader("replacement"), before: func() {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}}
	if err := writeFile(path, reader, 0644, false); err == nil {
		t.Fatal("expected rename onto directory to fail")
	}
	checkNoTemps(t, dir)
}

func TestWriteRejectsDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "link")
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("replacement"), 0600); err == nil {
		t.Fatal("expected dangling symlink error")
	}
	if target, err := os.Readlink(path); err != nil || target != "missing" {
		t.Fatalf("dangling symlink changed: %q, %v", target, err)
	}
	checkNoTemps(t, dir)
}

func checkFile(t *testing.T, path, want string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != want {
		t.Fatalf("%s = %q, %v; want %q", path, data, err, want)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != mode {
		t.Fatalf("mode for %s = %v, %v; want %v", path, info, err, mode)
	}
}

func checkNoTemps(t *testing.T, dir string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, ".*.tmp-*"))
	if err != nil || len(paths) != 0 {
		t.Fatalf("temporary files remain: %v, %v", paths, err)
	}
}
