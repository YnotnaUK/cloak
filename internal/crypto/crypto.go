package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const Prefix = "CLOAK:v2:"

var ErrNoMatchingRecipient = errors.New("no matching recipient found for local private key")

// Encrypt encrypts plaintext with a random DEK, then wraps the DEK for each recipient.
func Encrypt(plaintext []byte, recipients []string) (string, error) {
	if len(recipients) == 0 {
		return "", errors.New("at least one recipient public key is required")
	}

	// 1. Generate a random 32-byte Data Encryption Key (DEK)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return "", fmt.Errorf("failed to generate data key: %w", err)
	}

	// 2. Encrypt plaintext with the DEK using AES-256-GCM
	dataBlock, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("failed to create data cipher: %w", err)
	}
	dataGcm, err := cipher.NewGCM(dataBlock)
	if err != nil {
		return "", fmt.Errorf("failed to create data gcm: %w", err)
	}

	dataNonce := make([]byte, dataGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dataNonce); err != nil {
		return "", fmt.Errorf("failed to generate data nonce: %w", err)
	}
	dataCiphertext := dataGcm.Seal(nil, dataNonce, plaintext, nil)

	// 3. Wrap DEK for each recipient
	curve := ecdh.X25519()
	var wrappedList []string

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

		sharedSecret, err := ephemPriv.ECDH(recipPub)
		if err != nil {
			return "", fmt.Errorf("ecdh failed: %w", err)
		}
		wrapKey := sha256.Sum256(sharedSecret)

		wrapBlock, err := aes.NewCipher(wrapKey[:])
		if err != nil {
			return "", fmt.Errorf("failed wrap cipher: %w", err)
		}
		wrapGcm, err := cipher.NewGCM(wrapBlock)
		if err != nil {
			return "", fmt.Errorf("failed wrap gcm: %w", err)
		}

		wrapNonce := make([]byte, wrapGcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, wrapNonce); err != nil {
			return "", fmt.Errorf("failed wrap nonce: %w", err)
		}

		wrappedDek := wrapGcm.Seal(nil, wrapNonce, dek, nil)

		// Each recipient wrap: ephemPub(32B):wrapNonce(12B):wrappedDek(48B) in hex
		entry := fmt.Sprintf("%s:%s:%s",
			hex.EncodeToString(ephemPriv.PublicKey().Bytes()),
			hex.EncodeToString(wrapNonce),
			hex.EncodeToString(wrappedDek),
		)
		wrappedList = append(wrappedList, entry)
	}

	// Format: CLOAK:v2:<dataNonce>:<dataCiphertext>|<recip1>,<recip2>,...
	return fmt.Sprintf("%s%s:%s|%s",
		Prefix,
		hex.EncodeToString(dataNonce),
		hex.EncodeToString(dataCiphertext),
		strings.Join(wrappedList, ","),
	), nil
}

// Decrypt unwraps the DEK using the local private key, then decrypts the payload.
func Decrypt(envelope string, privKeyHex string) ([]byte, error) {
	if !strings.HasPrefix(envelope, Prefix) {
		return nil, fmt.Errorf("invalid envelope prefix")
	}

	trimmed := strings.TrimPrefix(envelope, Prefix)
	parts := strings.SplitN(trimmed, "|", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed cloak v2 envelope")
	}

	dataParts := strings.Split(parts[0], ":")
	if len(dataParts) != 2 {
		return nil, fmt.Errorf("malformed data segment")
	}

	dataNonce, err := hex.DecodeString(dataParts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid data nonce hex: %w", err)
	}

	dataCiphertext, err := hex.DecodeString(dataParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid data ciphertext hex: %w", err)
	}

	// Load local private key
	privBytes, err := hex.DecodeString(strings.TrimSpace(privKeyHex))
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	curve := ecdh.X25519()
	localPriv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// 4. Try unwrapping the DEK from one of the recipient entries
	recipEntries := strings.Split(parts[1], ",")
	var dek []byte

	for _, entry := range recipEntries {
		entryParts := strings.Split(entry, ":")
		if len(entryParts) != 3 {
			continue
		}

		ephemPubBytes, err := hex.DecodeString(entryParts[0])
		if err != nil {
			continue
		}

		wrapNonce, err := hex.DecodeString(entryParts[1])
		if err != nil {
			continue
		}

		wrappedDek, err := hex.DecodeString(entryParts[2])
		if err != nil {
			continue
		}

		ephemPub, err := curve.NewPublicKey(ephemPubBytes)
		if err != nil {
			continue
		}

		sharedSecret, err := localPriv.ECDH(ephemPub)
		if err != nil {
			continue
		}
		wrapKey := sha256.Sum256(sharedSecret)

		wrapBlock, err := aes.NewCipher(wrapKey[:])
		if err != nil {
			continue
		}

		wrapGcm, err := cipher.NewGCM(wrapBlock)
		if err != nil {
			continue
		}

		unwrapped, err := wrapGcm.Open(nil, wrapNonce, wrappedDek, nil)
		if err == nil {
			dek = unwrapped
			break
		}
	}

	if dek == nil {
		return nil, ErrNoMatchingRecipient
	}

	// 5. Decrypt data ciphertext with recovered DEK
	dataBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed data cipher: %w", err)
	}

	dataGcm, err := cipher.NewGCM(dataBlock)
	if err != nil {
		return nil, fmt.Errorf("failed data gcm: %w", err)
	}

	return dataGcm.Open(nil, dataNonce, dataCiphertext, nil)
}
