package session

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"net/http"
)

var DefaultCookieTemplate = &http.Cookie{
	HttpOnly: true,
	Path:     "/",
	SameSite: http.SameSiteLaxMode,
}

// use https://github.com/golang/go/issues/67057#issuecomment-2261204789 when released
func newSID() string {
	var b = make([]byte, 128/8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("err getting random")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
