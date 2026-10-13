package engine

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/ynotnauk/cloak/internal/config"
)

func newTestRecipient(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(privateKey.PublicKey().Bytes()), hex.EncodeToString(privateKey.Bytes())
}

func TestRekeyWithConfigAddsRecipientTransactionally(t *testing.T) {
	setup(t, "app.yaml", "password: secret\n")
	publicKey, privateKey := newTestRecipient(t)

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	updated, err := cfg.WithAddedRecipient("new-user", publicKey, config.KindUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := RekeyWithConfig(updated); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat("app.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("rekeyed file mode = %v, want 0640", info.Mode().Perm())
	}

	SetKeyLoader(func() (string, error) { return privateKey, nil })
	plaintext, err := DecryptFile("app.yaml")
	if err != nil || string(plaintext) != "password: secret\n" {
		t.Fatalf("new recipient decrypt = %q, %v", plaintext, err)
	}

	saved, err := config.Load()
	if err != nil || len(saved.Recipients) != 2 {
		t.Fatalf("saved recipients = %v, %v", saved, err)
	}
}

func TestRekeyIgnoresReservedPrefixesInUnencryptedFields(t *testing.T) {
	setup(t, "app.yaml", "password: secret\n")
	note := []byte("# CLOAK[ in a comment\nnote: CLOAK[v1,not-an-envelope]\n")
	if err := os.WriteFile("note.yaml", note, 0640); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := newTestRecipient(t)
	updated, err := cfg.WithAddedRecipient("new-user", publicKey, config.KindUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := RekeyWithConfig(updated); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile("note.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(note) {
		t.Fatalf("unencrypted file was changed during rekey:\n%s", after)
	}
}

func TestRekeyWithConfigRemovalRevokesRecipient(t *testing.T) {
	setup(t, "app.yaml", "password: secret\n")
	oldPrivateKey, err := cryptoPrivateKeyLoader()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := newTestRecipient(t)

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddRecipient("retained", publicKey, config.KindUser); err != nil {
		t.Fatal(err)
	}
	updated, removed, err := cfg.WithoutRecipient("me")
	if err != nil {
		t.Fatal(err)
	}
	if removed.Name != "me" {
		t.Fatalf("removed recipient = %q, want me", removed.Name)
	}
	if err := RekeyWithConfig(updated); err != nil {
		t.Fatal(err)
	}

	SetKeyLoader(func() (string, error) { return privateKey, nil })
	plaintext, err := DecryptFile("app.yaml")
	if err != nil || string(plaintext) != "password: secret\n" {
		t.Fatalf("retained recipient decrypt = %q, %v", plaintext, err)
	}

	SetKeyLoader(func() (string, error) { return oldPrivateKey, nil })
	if _, err := DecryptFile("app.yaml"); err == nil {
		t.Fatal("removed recipient can still decrypt rekeyed file")
	}
}

func TestRekeyWithConfigPreflightsEveryFileBeforeWriting(t *testing.T) {
	setup(t, "a.yaml", "password: secret\n")
	if err := os.WriteFile("z.yaml", []byte("password: CLOAK[v1,invalid]\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := newTestRecipient(t)
	updated, err := cfg.WithAddedRecipient("new-user", publicKey, config.KindUser)
	if err != nil {
		t.Fatal(err)
	}
	originalFile, err := os.ReadFile("a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	originalConfig, err := os.ReadFile(config.ConfigFileName)
	if err != nil {
		t.Fatal(err)
	}

	if err := RekeyWithConfig(updated); err == nil {
		t.Fatal("expected malformed envelope to fail rekeying")
	}
	afterFile, err := os.ReadFile("a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(afterFile) != string(originalFile) {
		t.Fatal("file was modified before all files passed rekeying")
	}
	afterConfig, err := os.ReadFile(config.ConfigFileName)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterConfig) != string(originalConfig) {
		t.Fatal("config was saved despite rekey failure")
	}
}

func TestRekeyWithConfigRestoresFilesWhenConfigSaveFails(t *testing.T) {
	setup(t, "app.yaml", "password: secret\n")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := newTestRecipient(t)
	updated, err := cfg.WithAddedRecipient("new-user", publicKey, config.KindUser)
	if err != nil {
		t.Fatal(err)
	}
	originalFile, err := os.ReadFile("app.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configBackup := t.TempDir() + "/cloak.yaml"
	if err := os.Rename(config.ConfigFileName, configBackup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(config.ConfigFileName, 0700); err != nil {
		if renameErr := os.Rename(configBackup, config.ConfigFileName); renameErr != nil {
			t.Fatalf("creating config directory failed: %v; restoring config failed: %v", err, renameErr)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(config.ConfigFileName); err == nil {
			if err := os.Rename(configBackup, config.ConfigFileName); err != nil {
				t.Errorf("restoring config after test: %v", err)
			}
		}
	})

	if err := RekeyWithConfig(updated); err == nil {
		t.Fatal("expected config save failure")
	}
	afterFile, err := os.ReadFile("app.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(afterFile) != string(originalFile) {
		t.Fatal("file was not restored after config save failure")
	}
}
