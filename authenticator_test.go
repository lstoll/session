package session

import (
	"bytes"
	"errors"
	"testing"
)

func TestHMACSHA256AuthenticatorRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)
	message := []byte("session id")

	old, err := NewHMACSHA256Authenticator(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldTag, err := old.Authenticate(message)
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := NewHMACSHA256Authenticator(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotated.Verify(message, oldTag); err != nil {
		t.Fatalf("previous-key authenticator rejected: %v", err)
	}

	newTag, err := rotated.Authenticate(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Verify(message, newTag); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("new authenticator accepted by old key: %v", err)
	}
	if err := rotated.Verify([]byte("different"), newTag); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("authenticator accepted for different message: %v", err)
	}
}

func TestHMACSHA256AuthenticatorRejectsShortKeys(t *testing.T) {
	if _, err := NewHMACSHA256Authenticator(make([]byte, 31)); err == nil {
		t.Fatal("short current key accepted")
	}
	if _, err := NewHMACSHA256Authenticator(make([]byte, 32), make([]byte, 31)); err == nil {
		t.Fatal("short previous key accepted")
	}
}

func TestHMACSHA256AuthenticatorCopiesKeys(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	authenticator, err := NewHMACSHA256Authenticator(key)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := authenticator.Authenticate([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	if err := authenticator.Verify([]byte("message"), tag); err != nil {
		t.Fatalf("mutating caller key changed authenticator: %v", err)
	}
}
