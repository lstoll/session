package session

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestCodecRoundTrip(t *testing.T) {
	now := time.Date(2026, time.August, 14, 12, 30, 0, 0, time.UTC)
	wantData := testSessionData{User: "alice", Value: "value0"}
	wantMeta := sessionMeta{
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
			codec, err := resolveCodec(tt.selector)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := codec.MarshalPayload(&wantData)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := codec.Encode(wantMeta, payload)
			if err != nil {
				t.Fatal(err)
			}
			if tt.isJSON && !json.Valid(encoded) {
				t.Fatalf("JSON codec produced invalid JSON: %q", encoded)
			}
			gotMeta, gotPayload, err := codec.Decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var gotData testSessionData
			if err := codec.UnmarshalPayload(gotPayload, &gotData); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotMeta, wantMeta) || !reflect.DeepEqual(gotData, wantData) {
				t.Fatalf("round trip mismatch:\n got: %#v %#v\nwant: %#v %#v", gotMeta, gotData, wantMeta, wantData)
			}
		})
	}
}

func TestManagerCodecSelection(t *testing.T) {
	defaultManager, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := defaultManager.codec.(*jsonCodec); !ok {
		t.Fatalf("default codec = %T, want JSON", defaultManager.codec)
	}

	gobManager, err := NewKVManager[testSessionData](NewMemoryKV(), &KVManagerOpts[testSessionData]{
		Codec: GobCodec{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gobManager.codec.(*gobCodec); !ok {
		t.Fatalf("selected codec = %T, want gob", gobManager.codec)
	}
}

func TestJSONCodecCarriesPayload(t *testing.T) {
	c := &jsonCodec{}
	payload := []byte(`{ "User": "alice" }`)
	encoded, err := c.Encode(sessionMeta{CreatedAt: time.Now()}, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, gotPayload, err := c.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var got testSessionData
	if err := c.UnmarshalPayload(gotPayload, &got); err != nil {
		t.Fatal(err)
	}
	if got.User != "alice" {
		t.Fatalf("decoded payload = %#v", got)
	}
}
