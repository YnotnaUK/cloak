package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
)

type KeyPair struct {
	Private string
	Public  string
}

func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		Private: base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		Public:  base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}
