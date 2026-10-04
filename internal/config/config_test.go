package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func newKey(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k.PublicKey().Bytes())
}

func TestRecipientLifecycle(t *testing.T) {
	t.Chdir(t.TempDir())
	k1, k2 := newKey(t), newKey(t)

	if err := Init([]Recipient{{Name: "alice", Key: k1}}, false); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Recipients[0].Kind != KindUser {
		t.Errorf("kind = %q, want default user", cfg.Recipients[0].Kind)
	}

	tests := []struct {
		name, key, kind string
		wantErr         bool
	}{
		{"alice", k2, KindCI, true},      // duplicate name
		{"dup", k1, KindCI, true},        // duplicate key
		{"bad", "zz", KindCI, true},      // invalid key
		{"x", k2, "robot", true},         // invalid kind
		{"", k2, KindCI, true},           // missing name
		{"ci-deploy", k2, KindCI, false}, // valid
	}
	for _, tc := range tests {
		err := cfg.AddRecipient(tc.name, tc.key, tc.kind)
		if (err != nil) != tc.wantErr {
			t.Errorf("AddRecipient(%q): err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}

	cfg, err = Load()
	if err != nil || len(cfg.Recipients) != 2 {
		t.Fatalf("reload: %v, %d recipients", err, len(cfg.Recipients))
	}

	if _, err := cfg.RemoveRecipient("ci-deploy"); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.RemoveRecipient(k1); err == nil {
		t.Error("expected error removing last recipient")
	}
}
