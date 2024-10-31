package session

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"io"
	"net/http"
)

var DefaultCookieTemplate = &http.Cookie{
	HttpOnly: true,
	Path:     "/",
	SameSite: http.SameSiteLaxMode,
}

var ErrNotFound = errors.New("session not found")

type Store interface {
	// Get loads and unmarshals the session in to into
	Get(r *http.Request, into any) (loaded bool, _ error)
	// Put saves a session. If a session exists it should be updated, otherwise
	// a new session should be created.
	Put(w http.ResponseWriter, r *http.Request, value any) error
	// Delete deletes the session.
	Delete(w http.ResponseWriter, r *http.Request) error
}

type Session interface {
	Get(r *http.Request, into any) (loaded bool, _ error)
	// Put saves a session. If a session exists it should be updated, otherwise
	// a new session should be created.
	Put(w http.ResponseWriter, r *http.Request, value any) error
	// Delete deletes the session.
	Delete(w http.ResponseWriter, r *http.Request) error
}

// use https://github.com/golang/go/issues/67057#issuecomment-2261204789 when released
func newSID() string {
	var b = make([]byte, 128/8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("err getting random")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
