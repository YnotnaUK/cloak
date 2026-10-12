package config

import (
	"os"
	"testing"
)

func TestConfigWritesReplaceAtomically(t *testing.T) {
	for _, operation := range []string{"save", "force init"} {
		t.Run(operation, func(t *testing.T) {
			t.Chdir(t.TempDir())
			recipients := []Recipient{{Name: "me", Key: newKey(t)}}
			if err := Init(recipients, false); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(ConfigFileName, 0600); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(ConfigFileName)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Link(ConfigFileName, "original"); err != nil {
				t.Fatal(err)
			}
			if operation == "save" {
				cfg, err := Load()
				if err != nil {
					t.Fatal(err)
				}
				cfg.Exclude = append(cfg.Exclude, "extra")
				if err := cfg.Save(); err != nil {
					t.Fatal(err)
				}
			} else if err := Init(recipients, true); err != nil {
				t.Fatal(err)
			}
			beforeInfo, err := os.Stat("original")
			if err != nil {
				t.Fatal(err)
			}
			afterInfo, err := os.Stat(ConfigFileName)
			if err != nil {
				t.Fatal(err)
			}
			if os.SameFile(beforeInfo, afterInfo) || afterInfo.Mode().Perm() != 0600 {
				t.Fatal("config not atomically replaced with original mode")
			}
			data, err := os.ReadFile("original")
			if err != nil || string(data) != string(original) {
				t.Fatalf("original inode modified: %v", err)
			}
			if err := Init(recipients, false); err == nil {
				t.Fatal("init overwrote existing config without force")
			}
		})
	}
}
