package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go/v2/tink"
)

type cookieStore[T any] struct {
	aead                tink.AEAD
	codec               codec[T]
	compressionDisabled bool
	cookieSettings      SessionCookieOpts
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
	if magic != managerCompressedCookieMagic && magic != managerCookieMagic {
		return persistedSession[T]{}, nil, nil
	}

	// Decrypt using AEAD with domain separated AD
	decryptedData, err := s.aead.Decrypt(decodedData, []byte(s.cookieSettings.Name))
	if err != nil {
		return persistedSession[T]{}, nil, nil
	}

	// Decompress if needed
	var rawData []byte
	if magic == managerCompressedCookieMagic {
		cr := getDecompressor()
		defer putDecompressor(cr)
		b, err := cr.Decompress(decryptedData)
		if err != nil {
			return persistedSession[T]{}, nil, fmt.Errorf("decompressing cookie: %w", err)
		}
		rawData = b
	} else {
		rawData = decryptedData
	}

	// Check expiry
	if len(rawData) < 8 {
		return persistedSession[T]{}, nil, errors.New("decrypted data too short")
	}
	expiresAt := time.Unix(int64(binary.LittleEndian.Uint64(rawData[:8])), 0)
	if expiresAt.Before(time.Now()) {
		return persistedSession[T]{}, nil, nil
	}

	// Decode using the codec
	sess, err := s.codec.Decode(rawData[8:])
	if err != nil {
		return persistedSession[T]{}, nil, fmt.Errorf("decoding session: %w", err)
	}

	return sess, rawData[8:], nil
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

	// Apply compression if needed
	magic := managerCookieMagic
	if !s.compressionDisabled && len(dataWithExpiry) > managerCompressThreshold {
		cw := getCompressor()
		defer putCompressor(cw)

		b, err := cw.Compress(dataWithExpiry)
		if err != nil {
			return fmt.Errorf("compressing cookie: %w", err)
		}
		dataWithExpiry = b
		magic = managerCompressedCookieMagic
	}

	// Encrypt data with AEAD
	encryptedData, err := s.aead.Encrypt(dataWithExpiry, []byte(s.cookieSettings.Name))
	if err != nil {
		return fmt.Errorf("encrypting cookie failed: %w", err)
	}

	// Format cookie value: magic.encodedData
	cookieValue := magic + "." + managerCookieValueEncoding.EncodeToString(encryptedData)
	if len(cookieValue) > managerMaxCookieSize {
		return fmt.Errorf("cookie size %d is greater than max %d", len(cookieValue), managerMaxCookieSize)
	}

	// Set cookie
	cookie := s.cookieSettings.newCookie(expiresAt)
	cookie.Value = cookieValue

	http.SetCookie(w, cookie)

	return nil
}

func (s *cookieStore[T]) delete(r *http.Request) error {
	return nil
}

func (s *cookieStore[T]) touch(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error {
	return s.writeCookie(w, expiresAt, data)
}
