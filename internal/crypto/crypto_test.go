package crypto_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ynotnauk/cloak/internal/crypto"
)

func TestEncryptDecrypt(t *testing.T) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pubHex := hex.EncodeToString(priv.PublicKey().Bytes())
	privHex := hex.EncodeToString(priv.Bytes())

	original := "super_secret_value_42"

	encrypted, err := crypto.Encrypt([]byte(original), pubHex)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(encrypted, privHex)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != original {
		t.Fatalf("expected %q, got %q", original, string(decrypted))
	}
}
