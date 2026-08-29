package session

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"time"
)

// Codec selects the encoding used for persisted sessions. Managers sharing a
// store must use the same codec. Changing it invalidates existing sessions.
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

type codec interface {
	Encode(meta sessionMeta, payload []byte) ([]byte, error)
	Decode(data []byte) (sessionMeta, []byte, error)
	MarshalPayload(any) ([]byte, error)
	UnmarshalPayload([]byte, any) error
}

// sessionMeta is the persistence envelope excluding application data.
type sessionMeta struct {
	CreatedAt                 time.Time       `json:"created_at"`
	UpdatedAt                 time.Time       `json:"updated_at,omitzero"`
	Flashes                   []Flash         `json:"flashes,omitempty"`
	DBSCAlgorithm             string          `json:"dbsc_algorithm,omitempty"`
	DBSCPublicJWK             []byte          `json:"dbsc_public_jwk,omitempty"`
	DBSCSessionID             string          `json:"dbsc_session_id,omitempty"`
	DBSCRegistrationChallenge dbscChallenge   `json:"dbsc_registration_challenge,omitzero"`
	DBSCExpiration            time.Time       `json:"dbsc_expiration,omitzero"`
	DBSCChallenges            []dbscChallenge `json:"dbsc_challenges,omitempty"`
	DBSCCurrentCookieID       string          `json:"dbsc_current_cookie_id,omitempty"`
}

type jsonCodec struct{}

// gobCodec uses a split envelope so metadata writes never decode or re-encode
// application data.
type gobCodec struct{}

type jsonEnvelope struct {
	Meta sessionMeta     `json:"meta"`
	Data json.RawMessage `json:"data"`
}

type gobEnvelope struct {
	Meta    sessionMeta
	Payload []byte
}

func resolveCodec(selected Codec) (codec, error) {
	switch selected.(type) {
	case nil, JSONCodec, *JSONCodec:
		return &jsonCodec{}, nil
	case GobCodec, *GobCodec:
		return &gobCodec{}, nil
	default:
		return nil, fmt.Errorf("unsupported session codec %T", selected)
	}
}

func (c *jsonCodec) Encode(meta sessionMeta, payload []byte) ([]byte, error) {
	data, err := json.Marshal(jsonEnvelope{Meta: meta, Data: json.RawMessage(payload)})
	if err != nil {
		return nil, fmt.Errorf("encoding session data: %w", err)
	}
	return data, nil
}

func (c *jsonCodec) Decode(data []byte) (sessionMeta, []byte, error) {
	var envelope jsonEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return sessionMeta{}, nil, fmt.Errorf("decoding session data: %w", err)
	}
	return envelope.Meta, envelope.Data, nil
}

func (g *gobCodec) Encode(meta sessionMeta, payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(gobEnvelope{Meta: meta, Payload: payload}); err != nil {
		return nil, fmt.Errorf("encoding session data: %w", err)
	}
	return buf.Bytes(), nil
}

func (g *gobCodec) Decode(data []byte) (sessionMeta, []byte, error) {
	var envelope gobEnvelope
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&envelope); err != nil {
		return sessionMeta{}, nil, fmt.Errorf("decoding session data: %w", err)
	}
	return envelope.Meta, envelope.Payload, nil
}

func (c *jsonCodec) MarshalPayload(data any) ([]byte, error) { return json.Marshal(data) }
func (c *jsonCodec) UnmarshalPayload(data []byte, dst any) error {
	return json.Unmarshal(data, dst)
}
func (g *gobCodec) MarshalPayload(data any) ([]byte, error) {
	var b bytes.Buffer
	err := gob.NewEncoder(&b).Encode(data)
	return b.Bytes(), err
}
func (g *gobCodec) UnmarshalPayload(data []byte, dst any) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(dst)
}
