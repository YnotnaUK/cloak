package engine

import (
	"os"
	"testing"
)

func TestSecretWritesReplaceAtomically(t *testing.T) {
	for _, operation := range []string{"encrypt", "decrypt", "edit", "rekey"} {
		for _, symlink := range []bool{false, true} {
			name := operation + "/regular"
			if symlink {
				name = operation + "/symlink"
			}
			t.Run(name, func(t *testing.T) {
				setup(t, "app.yaml", "password: old\n")
				path := "app.yaml"
				if operation == "encrypt" {
					if err := Process(true, []string{path}); err != nil {
						t.Fatal(err)
					}
				}
				if symlink {
					if err := os.Symlink(path, "link.yaml"); err != nil {
						t.Fatal(err)
					}
					path = "link.yaml"
				}
				original, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Link("app.yaml", "original"); err != nil {
					t.Fatal(err)
				}
				switch operation {
				case "encrypt":
					err = Process(false, []string{path})
				case "decrypt":
					err = Process(true, []string{path})
				case "edit":
					_, err = Edit(path, EditOptions{Run: replaceInFile("old", "new")})
				case "rekey":
					err = Rekey()
				}
				if err != nil {
					t.Fatal(err)
				}
				beforeInfo, err := os.Stat("original")
				if err != nil {
					t.Fatal(err)
				}
				afterInfo, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if os.SameFile(beforeInfo, afterInfo) || afterInfo.Mode().Perm() != 0640 {
					t.Fatal("secret not atomically replaced with original mode")
				}
				data, err := os.ReadFile("original")
				if err != nil || string(data) != string(original) {
					t.Fatalf("original inode modified: %v", err)
				}
				if symlink {
					if _, err := os.Readlink(path); err != nil {
						t.Fatalf("symlink was replaced: %v", err)
					}
				}
			})
		}
	}
}
