package session

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type cookieStore[T any] struct {
	aead           cipher.AEAD
	codec          codec[T]
	cookieSettings SessionCookieOpts
}

func (s *cookieStore[T]) load(r *http.Request) (persistedSession[T], []byte, error) {
	cookie, err := r.Cookie(s.cookieSettings.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return persistedSession[T]{}, nil, nil
		}
		return persistedSession[T]{}, nil, fmt.Errorf("getting cookie %s: %w", s.cookieSettings.Name, err)
	}

	cookieValue := cookie.Value

	// Split and validate format: magic.encodedData
	sp := strings.SplitN(cookieValue, ".", 2)
	if len(sp) != 2 {
		return persistedSession[T]{}, nil, nil
	}

	magic := sp[0]
	encodedData := sp[1]

	// Decode
	decodedData, err := managerCookieValueEncoding.DecodeString(encodedData)
	if err != nil {
		return persistedSession[T]{}, nil, nil
	}

	// Validate magic
	if magic != managerCookieMagic {
		return persistedSession[T]{}, nil, nil
	}

	// Decrypt using AEAD with domain separated AD
	decryptedData, err := openAEAD(s.aead, decodedData, []byte(s.cookieSettings.Name))
	if err != nil {
		return persistedSession[T]{}, nil, nil
	}

	// Check expiry
	if len(decryptedData) < 8 {
		return persistedSession[T]{}, nil, errors.New("decrypted data too short")
	}
	expiresAt := time.Unix(int64(binary.LittleEndian.Uint64(decryptedData[:8])), 0)
	if expiresAt.Before(time.Now()) {
		return persistedSession[T]{}, nil, nil
	}

	// Decode using the codec
	sess, err := s.codec.Decode(decryptedData[8:])
	if err != nil {
		return persistedSession[T]{}, nil, fmt.Errorf("decoding session: %w", err)
	}

	return sess, decryptedData[8:], nil
}

func (s *cookieStore[T]) save(w http.ResponseWriter, r *http.Request, expiresAt time.Time, sess persistedSession[T]) error {
	// Encode using the codec
	data, err := s.codec.Encode(sess)
	if err != nil {
		return fmt.Errorf("encoding session: %w", err)
	}

	return s.writeCookie(w, expiresAt, data)
}

func (s *cookieStore[T]) writeCookie(w http.ResponseWriter, expiresAt time.Time, data []byte) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(expiresAt.Unix()))
	dataWithExpiry := append(b, data...)

	// Encrypt data with AEAD
	encryptedData, err := sealAEAD(s.aead, dataWithExpiry, []byte(s.cookieSettings.Name))
	if err != nil {
		return fmt.Errorf("encrypting cookie failed: %w", err)
	}

	// Format cookie value: magic.encodedData
	cookieValue := managerCookieMagic + "." + managerCookieValueEncoding.EncodeToString(encryptedData)
	if len(cookieValue) > managerMaxCookieSize {
		return fmt.Errorf("cookie size %d is greater than max %d", len(cookieValue), managerMaxCookieSize)
	}

	// Set cookie
	cookie := s.cookieSettings.newCookie(expiresAt)
	cookie.Value = cookieValue

	http.SetCookie(w, cookie)

	return nil
}

// sealAEAD prefixes the nonce for conventional cipher.AEAD implementations.
// AEADs with a zero NonceSize, such as cipher.NewGCMWithRandomNonce, own their
// nonce framing and receive the plaintext directly.
func sealAEAD(aead cipher.AEAD, plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if len(nonce) > 0 {
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("generating AEAD nonce: %w", err)
		}
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return append(nonce, ciphertext...), nil
}

func openAEAD(aead cipher.AEAD, sealed, additionalData []byte) ([]byte, error) {
	nonceSize := aead.NonceSize()
	if len(sealed) < nonceSize+aead.Overhead() {
		return nil, errors.New("AEAD ciphertext too short")
	}
	return aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], additionalData)
}

//nolint:unused // Implements sessionStore; golangci-lint does not resolve the generic interface implementation.
func (s *cookieStore[T]) delete(r *http.Request) error {
	return nil
}

//nolint:unused // Implements sessionStore; golangci-lint does not resolve the generic interface implementation.
func (s *cookieStore[T]) touch(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error {
	return s.writeCookie(w, expiresAt, data)
}
