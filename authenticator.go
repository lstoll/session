package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

const minHMACSHA256KeySize = 32

// ErrAuthenticationFailed is returned when an authenticator does not match.
var ErrAuthenticationFailed = errors.New("authentication failed")

// Authenticator authenticates opaque values such as session IDs.
// Implementations must be safe for concurrent use.
type Authenticator interface {
	Authenticate(message []byte) ([]byte, error)
	Verify(message, authenticator []byte) error
}

// hmacSHA256Authenticator authenticates with HMAC-SHA-256 and supports key
// rotation. New authenticators use the current key; verification accepts the
// current key or any configured previous key.
type hmacSHA256Authenticator struct {
	keys [][]byte
}

var _ Authenticator = (*hmacSHA256Authenticator)(nil)

// NewHMACSHA256Authenticator creates a rotation-aware authenticator.
// Every key must contain at least 32 bytes of cryptographically random data.
func NewHMACSHA256Authenticator(currentKey []byte, previousKeys ...[]byte) (Authenticator, error) {
	keys := make([][]byte, 0, 1+len(previousKeys))
	for i, key := range append([][]byte{currentKey}, previousKeys...) {
		if len(key) < minHMACSHA256KeySize {
			return nil, fmt.Errorf("HMAC-SHA-256 key %d must be at least %d bytes", i, minHMACSHA256KeySize)
		}
		keys = append(keys, append([]byte(nil), key...))
	}
	return &hmacSHA256Authenticator{keys: keys}, nil
}

// Authenticate returns an HMAC made with the current key.
func (a *hmacSHA256Authenticator) Authenticate(message []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, a.keys[0])
	_, _ = mac.Write(message)
	return mac.Sum(nil), nil
}

// Verify accepts an HMAC made with the current key or a previous key.
func (a *hmacSHA256Authenticator) Verify(message, authenticator []byte) error {
	matched := false
	for _, key := range a.keys {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(message)
		matched = hmac.Equal(mac.Sum(nil), authenticator) || matched
	}
	if !matched {
		return ErrAuthenticationFailed
	}
	return nil
}
