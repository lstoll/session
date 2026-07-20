package session

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"
)

type codec[T any] interface {
	// Encode serializes the session data.
	Encode(sd persistedSession[T]) ([]byte, error)

	// Decode deserializes the session data.
	Decode(data []byte) (persistedSession[T], error)
}

// gobCodec is a codec that uses Go's gob encoding
type gobCodec[T any] struct{}

type flashLevel string

const (
	flashLevelNone  flashLevel = ""
	flashLevelInfo  flashLevel = "info"
	flashLevelError flashLevel = "error"
)

// persistedSession is the type that codecs are passed to serialize. Changes to
// this must be forward/backwards compatible. If we ever expose codec, we should
// think about stability beyond gob.
type persistedSession[T any] struct {
	Data      T
	CreatedAt time.Time
	UpdatedAt time.Time
	Flash     flashLevel
	FlashMsg  string

	// --- DBSC Fields ---
	// DBSCAlgorithm and DBSCPublicJWK identify the algorithm and single public
	// key established by the verified registration proof.
	DBSCAlgorithm string
	DBSCPublicJWK []byte
	// DBSCSessionID is the unique identifier sent to the browser during registration,
	// used to identify the session during a refresh (Sec-Secure-Session-Id).
	DBSCSessionID string
	// DBSCRegistrationChallenge is the pending, short-lived registration challenge.
	// It is cleared after registration completes.
	DBSCRegistrationChallenge dbscChallenge
	// DBSCExpiration tracks when the current "short-lived" proof expires.
	DBSCExpiration time.Time
	// DBSCChallenges contains the small set of recent refresh challenges that
	// may still be returned by the browser.
	DBSCChallenges []dbscChallenge
	// DBSCCurrentCookieID tracks the value of the short-lived device-bound cookie.
	DBSCCurrentCookieID string
}

func (g *gobCodec[T]) Encode(sess persistedSession[T]) ([]byte, error) {
	var buf bytes.Buffer

	if err := gob.NewEncoder(&buf).Encode(sess); err != nil {
		return nil, fmt.Errorf("encoding session data: %w", err)
	}

	return buf.Bytes(), nil
}

func (g *gobCodec[T]) Decode(data []byte) (persistedSession[T], error) {
	var result persistedSession[T]

	err := gob.NewDecoder(bytes.NewReader(data)).Decode(&result)
	if err != nil {
		return persistedSession[T]{}, fmt.Errorf("decoding session data: %w", err)
	}

	return result, nil
}
