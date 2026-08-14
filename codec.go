package session

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"time"
)

// Codec selects the encoding used for persisted sessions. The supported
// implementations are JSONCodec and GobCodec. All managers sharing a store
// must use the same codec; changing it invalidates existing sessions.
//
// Codec is sealed so the persistence envelope can evolve without exposing it
// as public API.
type Codec interface {
	sessionCodec()
}

// JSONCodec selects JSON session encoding. It is the default.
type JSONCodec struct{}

func (JSONCodec) sessionCodec() {}

// GobCodec selects Go gob session encoding.
type GobCodec struct{}

func (GobCodec) sessionCodec() {}

type codec[T any] interface {
	// Encode serializes the session data.
	Encode(sd persistedSession[T]) ([]byte, error)

	// Decode deserializes the session data.
	Decode(data []byte) (persistedSession[T], error)
}

type jsonCodec[T any] struct{}

// gobCodec is a codec that uses Go's gob encoding.
type gobCodec[T any] struct{}

// persistedSession is the private persistence envelope shared by the JSON and
// gob implementations. Keep field changes compatible with both encodings.
type persistedSession[T any] struct {
	Data      T         `json:"data"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	Flashes   []Flash   `json:"flashes,omitempty"`

	// --- DBSC Fields ---
	// DBSCAlgorithm and DBSCPublicJWK identify the algorithm and single public
	// key established by the verified registration proof.
	DBSCAlgorithm string `json:"dbsc_algorithm,omitempty"`
	DBSCPublicJWK []byte `json:"dbsc_public_jwk,omitempty"`
	// DBSCSessionID is the unique identifier sent to the browser during registration,
	// used to identify the session during a refresh (Sec-Secure-Session-Id).
	DBSCSessionID string `json:"dbsc_session_id,omitempty"`
	// DBSCRegistrationChallenge is the pending, short-lived registration challenge.
	// It is cleared after registration completes.
	DBSCRegistrationChallenge dbscChallenge `json:"dbsc_registration_challenge,omitzero"`
	// DBSCExpiration tracks when the current "short-lived" proof expires.
	DBSCExpiration time.Time `json:"dbsc_expiration,omitzero"`
	// DBSCChallenges contains the small set of recent refresh challenges that
	// may still be returned by the browser.
	DBSCChallenges []dbscChallenge `json:"dbsc_challenges,omitempty"`
	// DBSCCurrentCookieID tracks the value of the short-lived device-bound cookie.
	DBSCCurrentCookieID string `json:"dbsc_current_cookie_id,omitempty"`
}

func resolveCodec[T any](selected Codec) (codec[T], error) {
	switch selected.(type) {
	case nil, JSONCodec, *JSONCodec:
		return &jsonCodec[T]{}, nil
	case GobCodec, *GobCodec:
		return &gobCodec[T]{}, nil
	default:
		return nil, fmt.Errorf("unsupported session codec %T", selected)
	}
}

func (c *jsonCodec[T]) Encode(sess persistedSession[T]) ([]byte, error) {
	data, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("encoding session data: %w", err)
	}
	return data, nil
}

func (c *jsonCodec[T]) Decode(data []byte) (persistedSession[T], error) {
	var result persistedSession[T]
	if err := json.Unmarshal(data, &result); err != nil {
		return persistedSession[T]{}, fmt.Errorf("decoding session data: %w", err)
	}
	return result, nil
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
