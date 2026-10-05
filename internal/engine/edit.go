package engine

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ynotnauk/cloak/internal/crypto"
)

// EditOptions controls how Edit interacts with the user.
type EditOptions struct {
	// Run edits the plaintext file at the given path. Defaults to RunEditor.
	Run func(path string) error
	// Retry is asked whether to reopen the editor after the edited content
	// was rejected. Defaults to never retrying.
	Retry func(reason error) bool
}

// EditResult reports what Edit did.
type EditResult struct {
	Changed bool
	// KeptPath is set when the edit was rejected and the plaintext temp file was left in place.
	KeptPath string
}

// Edit decrypts a file into a private temporary file, lets the user edit it,
// and re-encrypts it on success. The temporary file is removed afterwards.
func Edit(path string, opts EditOptions) (res EditResult, err error) {
	cfg, formatter, content, privKey, rule, err := loadForRead(path)
	if err != nil {
		return res, err
	}
	clean := filepath.Clean(path)

	info, err := os.Stat(clean)
	if err != nil {
		return res, err
	}

	original, err := formatter.Decrypt(content, func(s string) ([]byte, error) {
		return crypto.Decrypt(s, privKey)
	})
	if err != nil {
		return res, fmt.Errorf("failed decrypting %s: %w", path, err)
	}

	run := opts.Run
	if run == nil {
		run = RunEditor
	}

	dir, err := os.MkdirTemp(os.Getenv("XDG_RUNTIME_DIR"), "cloak-edit-")
	if err != nil {
		return res, fmt.Errorf("failed creating temp dir: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()

	// The original base name is kept so editors can pick the right syntax highlighting.
	tmpPath := filepath.Join(dir, filepath.Base(clean))
	if err := os.WriteFile(tmpPath, original, 0600); err != nil {
		return res, fmt.Errorf("failed writing temp file: %w", err)
	}

	for {
		if err := run(tmpPath); err != nil {
			return res, fmt.Errorf("editor failed: %w", err)
		}

		edited, err := os.ReadFile(tmpPath)
		if err != nil {
			return res, fmt.Errorf("failed reading edited file: %w", err)
		}

		if bytes.Equal(edited, original) {
			return res, nil
		}

		encrypted, err := formatter.Encrypt(edited, rule.EncryptedKeys, func(b []byte) (string, error) {
			return crypto.Encrypt(b, cfg.Keys())
		})
		if err != nil {
			if opts.Retry != nil && opts.Retry(err) {
				continue
			}
			keep = true
			res.KeptPath = tmpPath
			return res, fmt.Errorf("edited content rejected, %s left unchanged: %w", path, err)
		}

		if err := os.WriteFile(clean, encrypted, info.Mode().Perm()); err != nil {
			return res, fmt.Errorf("failed writing %s: %w", path, err)
		}
		res.Changed = true
		return res, nil
	}
}

// editorCommand resolves the editor from $VISUAL, then $EDITOR, then vi.
func editorCommand() []string {
	for _, env := range []string{"VISUAL", "EDITOR"} {
		if fields := strings.Fields(os.Getenv(env)); len(fields) > 0 {
			return fields
		}
	}
	return []string{"vi"}
}

// RunEditor opens path in the user's editor and waits for it to exit.
func RunEditor(path string) error {
	argv := editorCommand()
	cmd := exec.Command(argv[0], append(argv[1:], path)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
