package session

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// rotatingAESGCM implements cipher.AEAD with key rotation. Seal always uses
// the current key; Open accepts ciphertext made with the current key or any
// configured previous key.
type rotatingAESGCM struct {
	keys []cipher.AEAD
}

var _ cipher.AEAD = (*rotatingAESGCM)(nil)

// NewRotatingAESGCM creates a rotation-aware AES-GCM cipher. Each key must be
// 16, 24, or 32 bytes. Prefer 32 random bytes for AES-256-GCM.
func NewRotatingAESGCM(currentKey []byte, previousKeys ...[]byte) (cipher.AEAD, error) {
	allKeys := append([][]byte{currentKey}, previousKeys...)
	aeads := make([]cipher.AEAD, 0, len(allKeys))
	for i, key := range allKeys {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES-GCM key %d: %w", i, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("creating AES-GCM key %d: %w", i, err)
		}
		aeads = append(aeads, aead)
	}
	return &rotatingAESGCM{keys: aeads}, nil
}

func (a *rotatingAESGCM) NonceSize() int { return a.keys[0].NonceSize() }

func (a *rotatingAESGCM) Overhead() int { return a.keys[0].Overhead() }

func (a *rotatingAESGCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return a.keys[0].Seal(dst, nonce, plaintext, additionalData)
}

func (a *rotatingAESGCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for _, key := range a.keys {
		plaintext, err := key.Open(nil, nonce, ciphertext, additionalData)
		if err == nil {
			return append(dst, plaintext...), nil
		}
	}
	return nil, errors.New("cipher: message authentication failed")
}
