package session

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultMaxAge = 30 * 24 * time.Hour

const (
	cookieMagic           = "EU1"
	compressedCookieMagic = "EC1"

	// compressThreshold is the size at which we decide to compress a cookie,
	// bytes
	compressThreshold = 512
	maxCookieSize     = 4096
)

var cookieValueEncoding = base64.RawURLEncoding

type CookieStore struct {
	AEAD                AEAD
	CookieTemplate      *http.Cookie
	Marshaler           Marshaler
	CompressionDisabled bool
}

// Get loads and unmarshals the session in to into
func (c *CookieStore) Get(r *http.Request, into any) (loaded bool, _ error) {
	// no active session loaded, try and fetch from cookie
	cookie, err := r.Cookie(c.CookieTemplate.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			// no session, no op
			return false, nil
		}
		return false, fmt.Errorf("getting cookie %s: %w", c.CookieTemplate.Name, err)
	}

	sp := strings.SplitN(cookie.Value, ".", 2)
	if len(sp) != 2 {
		return false, errors.New("cookie does not contain two . separated parts")
	}
	magic := sp[0]
	cd, err := cookieValueEncoding.DecodeString(sp[1])
	if err != nil {
		return false, fmt.Errorf("decoding cookie string: %w", err)
	}

	if magic != compressedCookieMagic && magic != cookieMagic {
		return false, fmt.Errorf("cooking has bad magic prefix: %s", magic)
	}

	// uncompress if needed
	if magic == compressedCookieMagic {
		cr := getDecompressor()
		defer putDecompressor(cr)
		b, err := cr.Decompress(cd)
		if err != nil {
			return false, fmt.Errorf("decompressing cookie: %w", err)
		}
		cd = b
	}

	// decrypt
	db, err := c.AEAD.Decrypt(cd, []byte(c.CookieTemplate.Name))
	if err != nil {
		return false, fmt.Errorf("decrypting cookie: %w", err)
	}

	expiresAt := time.Unix(int64(binary.LittleEndian.Uint64(db[:8])), 0)
	if expiresAt.Before(time.Now()) {
		return false, fmt.Errorf("cookie expired at %s", expiresAt)
	}
	db = db[8:]

	if err := c.Marshaler.Unmarshal(db, into); err != nil {
		return false, fmt.Errorf("unmarshaling cookie: %w", err)
	}

	return true, nil
}

// Put saves a session. If a session exists it should be updated, otherwise
// a new session should be created.
func (c *CookieStore) Put(w http.ResponseWriter, r *http.Request, value any) error {
	// marshal

	cb, err := c.Marshaler.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshaling cookie:")
	}

	// prepend an expiry time, so we can avoid things living forever.
	expiresIn := time.Duration(c.CookieTemplate.MaxAge) * time.Second
	if expiresIn == 0 {
		expiresIn = defaultMaxAge
	}
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(time.Now().Add(expiresIn).Unix()))
	cb = append(b, cb...)

	magic := cookieMagic
	if len(cb) > compressThreshold {
		cw := getCompressor()
		defer putCompressor(cw)

		b, err := cw.Compress(cb)
		if err != nil {
			return fmt.Errorf("compressing cookie: %w", err)
		}
		cb = b
		magic = compressedCookieMagic
	}

	cb, err = c.AEAD.Encrypt(cb, []byte(c.CookieTemplate.Name))
	if err != nil {
		return fmt.Errorf("encrypting cookie failed: %w", err)
	}

	cv := magic + "." + cookieValueEncoding.EncodeToString(cb)
	if len(cv) > maxCookieSize {
		return fmt.Errorf("cookie size %d is greater than max %d", len(cv), maxCookieSize)
	}

	cookie := c.newCookie()
	cookie.Value = cv
	http.SetCookie(w, cookie)

	return nil
}

// Delete deletes the session.
func (c *CookieStore) Delete(w http.ResponseWriter, r *http.Request) error {
	dc := c.newCookie()
	dc.MaxAge = -1
	http.SetCookie(w, dc)

	return nil
}

func (c *CookieStore) newCookie() *http.Cookie {
	cp := getOrDefault(c.CookieTemplate, DefaultCookieTemplate)
	nc := *cp
	return &nc
}
