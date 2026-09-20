package crypto

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	// 1. Generate the keypair
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("expected no error generating keypair, got: %v", err)
	}

	// 2. Verify Private Key is valid Base64 and exactly 32 bytes (256 bits)
	privBytes, err := base64.RawURLEncoding.DecodeString(kp.Private)
	if err != nil {
		t.Fatalf("private key is not valid URL-safe base64: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("expected private key to be 32 bytes, got %d", len(privBytes))
	}

	// 3. Verify Public Key is valid Base64 and exactly 32 bytes (256 bits)
	pubBytes, err := base64.RawURLEncoding.DecodeString(kp.Public)
	if err != nil {
		t.Fatalf("public key is not valid URL-safe base64: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("expected public key to be 32 bytes, got %d", len(pubBytes))
	}

	// 4. Mathematical check: Ensure the public key was actually derived from the private key
	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("failed to parse generated private key: %v", err)
	}

	derivedPubBytes := privKey.PublicKey().Bytes()
	if !bytes.Equal(pubBytes, derivedPubBytes) {
		t.Errorf("public key mismatch!\nexpected: %x\ngot:      %x", pubBytes, derivedPubBytes)
	}
}

func TestGenerateKeyPair_Uniqueness(t *testing.T) {
	// Generating two keys consecutively must yield completely different values
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate kp1: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate kp2: %v", err)
	}

	if kp1.Private == kp2.Private {
		t.Error("consecutive private keys must never be identical")
	}

	if kp1.Public == kp2.Public {
		t.Error("consecutive public keys must never be identical")
	}
}
