package session

import (
	"bytes"
	"testing"
)

func TestRotatingAESGCM(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	old, err := NewRotatingAESGCM(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewRotatingAESGCM(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}

	additionalData := []byte("cookie name")
	oldSealed, err := sealAEAD(old, []byte("old session"), additionalData)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openAEAD(rotated, oldSealed, additionalData)
	if err != nil || !bytes.Equal(opened, []byte("old session")) {
		t.Fatalf("opening with previous key = %q, %v", opened, err)
	}

	newSealed, err := sealAEAD(rotated, []byte("new session"), additionalData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openAEAD(old, newSealed, additionalData); err == nil {
		t.Fatal("new ciphertext opened with old key")
	}
	opened, err = openAEAD(rotated, newSealed, additionalData)
	if err != nil || !bytes.Equal(opened, []byte("new session")) {
		t.Fatalf("opening with current key = %q, %v", opened, err)
	}
}

func TestRotatingAESGCMRejectsInvalidKeys(t *testing.T) {
	if _, err := NewRotatingAESGCM(make([]byte, 15)); err == nil {
		t.Fatal("invalid current AES key accepted")
	}
	if _, err := NewRotatingAESGCM(make([]byte, 32), make([]byte, 15)); err == nil {
		t.Fatal("invalid previous AES key accepted")
	}
}
