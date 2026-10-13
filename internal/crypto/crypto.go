package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/ynotnauk/cloak/internal/envelope"
)

const (
	wrapInfo = "cloak v1 wrap"
	// dataAAD is bound into the payload tag so that ciphertext from another
	// protocol or version cannot be replayed as a Cloak v1 payload.
	dataAAD = "cloak v1 data"
)

var ErrNoMatchingRecipient = errors.New("no matching recipient found for local private key")

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// wrapKey derives the key-wrapping key, binding both public keys to the secret.
func wrapKey(shared, ephemPub, recipPub []byte) ([]byte, error) {
	salt := append(append([]byte{}, ephemPub...), recipPub...)
	return hkdf.Key(sha256.New, shared, salt, wrapInfo, 32)
}

func wrapAAD(dataIV []byte) []byte {
	return append([]byte(wrapInfo), dataIV...)
}

// Encrypt encrypts plaintext with a random DEK, then wraps the DEK for each recipient.
func Encrypt(plaintext []byte, recipients []string) (string, error) {
	if len(recipients) == 0 {
		return "", errors.New("at least one recipient public key is required")
	}
	if len(recipients) > envelope.MaxWraps {
		return "", fmt.Errorf("too many recipients (maximum %d)", envelope.MaxWraps)
	}

	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return "", fmt.Errorf("failed to generate data key: %w", err)
	}
	dataGcm, err := newGCM(dek)
	if err != nil {
		return "", fmt.Errorf("failed to create data cipher: %w", err)
	}
	dataIV := make([]byte, dataGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dataIV); err != nil {
		return "", fmt.Errorf("failed to generate data nonce: %w", err)
	}

	env := &envelope.Envelope{
		IV:   dataIV,
		Data: dataGcm.Seal(nil, dataIV, plaintext, []byte(dataAAD)),
	}

	curve := ecdh.X25519()
	for _, recipHex := range recipients {
		recipBytes, err := hex.DecodeString(strings.TrimSpace(recipHex))
		if err != nil {
			return "", fmt.Errorf("invalid recipient hex: %w", err)
		}
		recipPub, err := curve.NewPublicKey(recipBytes)
		if err != nil {
			return "", fmt.Errorf("invalid recipient public key: %w", err)
		}
		ephemPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("failed generating ephemeral key: %w", err)
		}
		shared, err := ephemPriv.ECDH(recipPub)
		if err != nil {
			return "", fmt.Errorf("ecdh failed: %w", err)
		}
		ephemPub := ephemPriv.PublicKey().Bytes()
		key, err := wrapKey(shared, ephemPub, recipPub.Bytes())
		if err != nil {
			return "", fmt.Errorf("failed deriving wrap key: %w", err)
		}
		wrapGcm, err := newGCM(key)
		if err != nil {
			return "", fmt.Errorf("failed wrap cipher: %w", err)
		}
		wrapIV := make([]byte, wrapGcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, wrapIV); err != nil {
			return "", fmt.Errorf("failed wrap nonce: %w", err)
		}
		env.Wraps = append(env.Wraps, envelope.Wrap{
			EphemeralPub: ephemPub,
			IV:           wrapIV,
			Key:          wrapGcm.Seal(nil, wrapIV, dek, wrapAAD(dataIV)),
		})
	}
	return env.String(), nil
}

// Decrypt unwraps the DEK using the local private key, then decrypts the payload.
func Decrypt(value string, privKeyHex string) ([]byte, error) {
	env, err := envelope.Parse(value)
	if err != nil {
		return nil, err
	}

	privBytes, err := hex.DecodeString(strings.TrimSpace(privKeyHex))
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	curve := ecdh.X25519()
	localPriv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	localPub := localPriv.PublicKey().Bytes()

	var dek []byte
	for _, w := range env.Wraps {
		ephemPub, err := curve.NewPublicKey(w.EphemeralPub)
		if err != nil {
			continue
		}
		shared, err := localPriv.ECDH(ephemPub)
		if err != nil {
			continue
		}
		key, err := wrapKey(shared, w.EphemeralPub, localPub)
		if err != nil {
			continue
		}
		wrapGcm, err := newGCM(key)
		if err != nil {
			continue
		}
		if unwrapped, err := wrapGcm.Open(nil, w.IV, w.Key, wrapAAD(env.IV)); err == nil {
			dek = unwrapped
			break
		}
	}
	if dek == nil {
		return nil, ErrNoMatchingRecipient
	}

	dataGcm, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("failed data cipher: %w", err)
	}
	plain, err := dataGcm.Open(nil, env.IV, env.Data, []byte(dataAAD))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate ciphertext: %w", err)
	}
	return plain, nil
}
