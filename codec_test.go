package session

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestCodecRoundTrip(t *testing.T) {
	now := time.Date(2026, time.August, 14, 12, 30, 0, 0, time.UTC)
	want := persistedSession[testSessionData]{
		Data:      testSessionData{User: "alice", Value: "value0"},
		CreatedAt: now,
		UpdatedAt: now.Add(time.Minute),
		Flashes: []Flash{
			{Level: FlashLevelInfo, Message: "hello"},
			{Level: FlashLevel("success"), Message: "done"},
		},
		DBSCAlgorithm:             "ES256",
		DBSCPublicJWK:             []byte(`{"kty":"EC"}`),
		DBSCSessionID:             "dbsc-session",
		DBSCRegistrationChallenge: dbscChallenge{Value: "registration", ExpiresAt: now.Add(time.Minute)},
		DBSCExpiration:            now.Add(time.Hour),
		DBSCChallenges:            []dbscChallenge{{Value: "refresh", ExpiresAt: now.Add(2 * time.Minute)}},
		DBSCCurrentCookieID:       "bound-cookie",
	}

	for _, tt := range []struct {
		name     string
		selector Codec
		isJSON   bool
	}{
		{name: "default JSON", isJSON: true},
		{name: "JSON", selector: JSONCodec{}, isJSON: true},
		{name: "gob", selector: GobCodec{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			codec, err := resolveCodec[testSessionData](tt.selector)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := codec.Encode(want)
			if err != nil {
				t.Fatal(err)
			}
			if tt.isJSON && !json.Valid(encoded) {
				t.Fatalf("JSON codec produced invalid JSON: %q", encoded)
			}
			got, err := codec.Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", got, want)
			}
		})
	}
}

func TestManagerCodecSelection(t *testing.T) {
	defaultManager, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := defaultManager.codec.(*jsonCodec[testSessionData]); !ok {
		t.Fatalf("default codec = %T, want JSON", defaultManager.codec)
	}

	gobManager, err := NewKVManager[testSessionData](NewMemoryKV(), &KVManagerOpts[testSessionData]{
		Codec: GobCodec{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gobManager.codec.(*gobCodec[testSessionData]); !ok {
		t.Fatalf("selected codec = %T, want gob", gobManager.codec)
	}
}
