package session

import (
	"testing"
)

func TestGobEncoding(t *testing.T) {
	// Create a sample data map similar to what's used in the E2E test
	data := testSessionData{
		User:  "alice",
		Value: "value0",
	}

	// Encode the data
	g := &gobCodec[testSessionData]{}
	encodedData, err := g.Encode(persistedSession[testSessionData]{
		Data: data,
	})
	if err != nil {
		t.Fatalf("Failed to encode: %v", err)
	}

	// Decode using the same codec
	decodedData, err := g.Decode(encodedData)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	// Check if values match
	if decodedData.Data != data {
		t.Fatalf("Data mismatch: %v", decodedData.Data)
	}
}
