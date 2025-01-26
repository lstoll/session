package session

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"net/http"
	"time"
)

var DefaultCookieTemplate = &http.Cookie{
	HttpOnly: true,
	Path:     "/",
	SameSite: http.SameSiteLaxMode,
}

// var ErrNotFound = errors.New("session not found")

type Store interface {
	// Get loads the encoded data for a session from the request. If there is no
	// session data, it should return nil
	Get(r *http.Request) ([]byte, error)
	// Put saves a session. If a session exists it should be updated, otherwise
	// a new session should be created.
	Put(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error
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
