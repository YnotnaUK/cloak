package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const Prefix = "CLOAK:v1:"

// Encrypt encrypts plaintext using an ephemeral X25519 key and AES-256-GCM.
func Encrypt(plaintext []byte, recipientHex string) (string, error) {
	recipientBytes, err := hex.DecodeString(recipientHex)
	if err != nil {
		return "", fmt.Errorf("invalid recipient public key hex: %w", err)
	}

	curve := ecdh.X25519()
	recipientPub, err := curve.NewPublicKey(recipientBytes)
	if err != nil {
		return "", fmt.Errorf("invalid recipient public key: %w", err)
	}

	// 1. Generate ephemeral keypair
	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPub := ephemeralPriv.PublicKey()

	// 2. ECDH shared secret & derive AES key via SHA-256
	sharedSecret, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return "", fmt.Errorf("ecdh computation failed: %w", err)
	}
	aesKey := sha256.Sum256(sharedSecret)

	// 3. Encrypt with AES-256-GCM
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: CLOAK:v1:<ephemPubHex>:<nonceHex>:<ciphertextHex>
	return fmt.Sprintf("%s%s:%s:%s",
		Prefix,
		hex.EncodeToString(ephemeralPub.Bytes()),
		hex.EncodeToString(nonce),
		hex.EncodeToString(ciphertext),
	), nil
}

// Decrypt decrypts a CLOAK:v1 payload using the local private key hex.
func Decrypt(envelope string, privKeyHex string) ([]byte, error) {
	if !strings.HasPrefix(envelope, Prefix) {
		return nil, fmt.Errorf("invalid envelope prefix")
	}

	parts := strings.Split(strings.TrimPrefix(envelope, Prefix), ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed cloak payload")
	}

	ephemPubBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key hex: %w", err)
	}

	nonce, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}

	ciphertext, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext hex: %w", err)
	}

	// Load local private key
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	ephemPub, err := curve.NewPublicKey(ephemPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// 1. Recover shared secret & AES key
	sharedSecret, err := privKey.ECDH(ephemPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh computation failed: %w", err)
	}
	aesKey := sha256.Sum256(sharedSecret)

	// 2. Decrypt with AES-GCM
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	return gcm.Open(nil, nonce, ciphertext, nil)
}
