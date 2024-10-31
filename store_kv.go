package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

type KV interface {
	Get(_ context.Context, key string) (_ []byte, found bool, _ error)
	Set(_ context.Context, key string, value []byte) error
	Delete(_ context.Context, key string) error
}

type KVStore struct {
	KV             KV
	CookieTemplate *http.Cookie
	Marshaler      Marshaler
}

// Get loads and unmarshals the session in to into
func (k *KVStore) Get(r *http.Request, into any) (loaded bool, _ error) {
	if into == nil {
		return false, errors.New("into can not be nil")
	}

	kvSess := k.getOrInitKVSess(r)

	// differentiate deleted vs. emptied

	if kvSess.id == "" {
		// no active session loaded, try and fetch from cookie
		cookie, err := r.Cookie(k.cookieName())
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				kvSess.id = newSID()
				return false, nil
			}
			return false, fmt.Errorf("getting cookie %s: %w", k.cookieName(), err)
		}
		kvSess.id = cookie.Value
	}

	b, ok, err := k.KV.Get(r.Context(), kvSess.id)
	if err != nil {
		return false, fmt.Errorf("loading from KV: %w", err)
	}
	if !ok {
		return false, nil
	}

	if err := getOrDefault(k.Marshaler, DefaultMarshaler).Unmarshal(b, into); err != nil {
		return false, fmt.Errorf("unmarshaling: %w", err)
	}

	return true, nil
}

// Put saves a session. If a session exists it should be updated, otherwise
// a new session should be created.
func (k *KVStore) Put(w http.ResponseWriter, r *http.Request, value any) error {
	b, err := getOrDefault(k.Marshaler, DefaultMarshaler).Marshal(value)
	if err != nil {
		return fmt.Errorf("marshaling: %w", err)
	}

	kvSess := k.getOrInitKVSess(r)
	if kvSess.id == "" {
		kvSess.id = newSID()
	}

	if err := k.KV.Set(r.Context(), kvSess.id, b); err != nil {
		return fmt.Errorf("putting session data: %w", err)
	}

	c := k.newCookie()
	c.Name = k.cookieName()
	c.Value = kvSess.id
	http.SetCookie(w, c)

	return nil
}

// Delete deletes the session.
func (k *KVStore) Delete(w http.ResponseWriter, r *http.Request) error {
	kvSess := k.getOrInitKVSess(r)
	if kvSess.id == "" {
		kvSess.id = newSID()
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

func (k *KVStore) cookieName() string {
	if k.CookieTemplate != nil && k.CookieTemplate.Name != "" {
		return k.CookieTemplate.Name
	}
	return "session-id"
}

func (k *KVStore) newCookie() *http.Cookie {
	cp := getOrDefault(k.CookieTemplate, DefaultCookieTemplate)
	nc := *cp
	return &nc
}

func (k *KVStore) getOrInitKVSess(r *http.Request) *kvSession {
	kvSess, ok := r.Context().Value(kvSessCtxKey{}).(*kvSession)
	if ok {
		return kvSess
	}

	kvSess = &kvSession{}
	*r = *r.WithContext(context.WithValue(r.Context(), kvSessCtxKey{}, kvSess))

	return kvSess
}

func getOrDefault[T comparable](check T, defaulted T) T {
	var nilt T
	if check != nilt {
		return check
	}
	return defaulted
}

type kvSessCtxKey struct{}

// kvSession tracks information across the session.
type kvSession struct {
	id string
}
