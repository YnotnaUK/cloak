package crypto_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/ynotnauk/cloak/internal/crypto"
)

func generateTestKeyPair(t *testing.T) (string, string) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(priv.PublicKey().Bytes()), hex.EncodeToString(priv.Bytes())
}

func TestMultiRecipientEncryptDecrypt(t *testing.T) {
	pub1, priv1 := generateTestKeyPair(t)
	pub2, priv2 := generateTestKeyPair(t)
	_, nonMemberPriv := generateTestKeyPair(t)

	original := "shared_team_secret_42"

	// Encrypt for both team members
	envelope, err := crypto.Encrypt([]byte(original), []string{pub1, pub2})
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Member 1 can decrypt
	dec1, err := crypto.Decrypt(envelope, priv1)
	if err != nil || string(dec1) != original {
		t.Fatalf("member 1 failed decrypt: %v, got %q", err, string(dec1))
	}

	// Member 2 can decrypt
	dec2, err := crypto.Decrypt(envelope, priv2)
	if err != nil || string(dec2) != original {
		t.Fatalf("member 2 failed decrypt: %v, got %q", err, string(dec2))
	}

	// Non-member fails to decrypt
	_, err = crypto.Decrypt(envelope, nonMemberPriv)
	if err != crypto.ErrNoMatchingRecipient {
		t.Fatalf("expected ErrNoMatchingRecipient, got: %v", err)
	}
}
