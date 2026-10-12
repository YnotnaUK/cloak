package fileio

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFile atomically replaces a file, preserving existing permissions and
// following symlinks. mode, subject to umask, is used only for new destinations.
func WriteFile(path string, data []byte, mode fs.FileMode) error {
	return writeFile(path, bytes.NewReader(data), mode, false)
}

// CreateFile atomically creates a file with mode subject to umask, without
// replacing an existing path.
func CreateFile(path string, data []byte, mode fs.FileMode) error {
	return writeFile(path, bytes.NewReader(data), mode, true)
}

func writeFile(path string, data io.Reader, mode fs.FileMode, exclusive bool) (err error) {
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if exclusive {
			return &os.PathError{Op: "create", Path: path, Err: fs.ErrExist}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			path, err = filepath.EvalSymlinks(path)
			if err != nil {
				return err
			}
			info, err = os.Stat(path)
			if err != nil {
				return err
			}
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("cannot replace non-regular file %s", path)
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}

	tempMode := mode
	if statErr == nil {
		tempMode = 0600
	}
	file, err := createTemp(path, tempMode)
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
		if cleanupErr := os.Remove(tmpPath); cleanupErr != nil && !errors.Is(cleanupErr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("failed removing temporary file %s: %w", tmpPath, cleanupErr))
		}
	}()

	if _, err := io.Copy(file, data); err != nil {
		return err
	}
	if statErr == nil {
		if err := file.Chmod(mode); err != nil {
			return err
		}
	}
	if err := file.Sync(); err != nil {
		return err
	}
	err = file.Close()
	closed = true
	if err != nil {
		return err
	}
	if exclusive {
		// Linking publishes the complete file without overwriting a racing creator.
		return os.Link(tmpPath, path)
	}
	return os.Rename(tmpPath, path)
}

func createTemp(path string, mode fs.FileMode) (*os.File, error) {
	for range 100 {
		tmpPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+rand.Text())
		file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return file, err
	}
	return nil, fmt.Errorf("failed creating temporary file for %s: %w", path, fs.ErrExist)
}
