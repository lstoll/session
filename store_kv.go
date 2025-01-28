package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type kvStore struct {
	KV         KV
	CookieOpts *CookieOpts
}

// get loads and unmarshals the session in to into
func (k *kvStore) get(r *http.Request) ([]byte, error) {
	kvSess := k.getOrInitKVSess(r)

	// TODO(lstoll) differentiate deleted vs. emptied

	if kvSess.id == "" {
		// no active session loaded, try and fetch from cookie
		cookie, err := r.Cookie(k.cookieName())
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				// kvSess.id = newSID()
				return nil, nil
			}
			return nil, fmt.Errorf("getting cookie %s: %w", k.cookieName(), err)
		}
		kvSess.id = cookie.Value
	}

	b, ok, err := k.KV.Get(r.Context(), kvSess.id)
	if err != nil {
		return nil, fmt.Errorf("loading from KV: %w", err)
	}
	if !ok {
		return nil, nil
	}

	return b, nil
}

// put saves a session. If a session exists it should be updated, otherwise
// a new session should be created.
func (k *kvStore) put(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error {
	kvSess := k.getOrInitKVSess(r)
	if kvSess.id == "" {
		kvSess.id = newSID()
	}

	if err := k.KV.Set(r.Context(), kvSess.id, expiresAt, data); err != nil {
		return fmt.Errorf("putting session data: %w", err)
	}

	c := k.newCookie()
	c.Expires = expiresAt
	c.Value = kvSess.id
	http.SetCookie(w, c)

	return nil
}

// delete deletes the session.
func (k *kvStore) delete(w http.ResponseWriter, r *http.Request) error {
	kvSess := k.getOrInitKVSess(r)
	if kvSess.id == "" {
		// no session ID to delete
		return nil
	}

	if err := k.KV.Delete(r.Context(), kvSess.id); err != nil {
		return fmt.Errorf("deleting session %s from store: %w", kvSess.id, err)
	}

	// always clear the cookie
	dc := k.newCookie()
	dc.Name = k.cookieName()
	dc.MaxAge = -1
	http.SetCookie(w, dc)

	// assign a fresh SID, so if we do save again it'll go under a new session.
	// If not, it's ignored. This prevents a `Get` from trying to re-load from
	// the cookie.
	kvSess.id = newSID()

	return nil
}

func (k *kvStore) cookieName() string {
	if k.CookieOpts != nil && k.CookieOpts.Name != "" {
		return k.CookieOpts.Name
	}
	return "session-id"
}

func (k *kvStore) newCookie() *http.Cookie {
	c := &http.Cookie{
		Name: k.cookieName(),
	}
	if k.CookieOpts == nil || !k.CookieOpts.Insecure {
		c.Secure = true
	}
	return c
}

func (k *kvStore) getOrInitKVSess(r *http.Request) *kvSession {
	kvSess, ok := r.Context().Value(kvSessCtxKey{inst: k}).(*kvSession)
	if ok {
		return kvSess
	}

	kvSess = &kvSession{}
	*r = *r.WithContext(context.WithValue(r.Context(), kvSessCtxKey{inst: k}, kvSess))

	return kvSess
}

func getOrDefault[T comparable](check T, defaulted T) T {
	var nilt T
	if check != nilt {
		return check
	}
	return defaulted
}

type kvSessCtxKey struct{ inst *kvStore }

// kvSession tracks information about the session across the request's context
type kvSession struct {
	id string
}
