package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type kvStore struct {
	kv         KV
	cookieOpts *CookieOpts
}

// get loads and unmarshals the session in to into
func (k *kvStore) get(r *http.Request) ([]byte, error) {
	kvSess := k.getOrInitKVSess(r)

	// TODO(lstoll) differentiate deleted vs. emptied

	if kvSess.id == "" {
		// no active session loaded, try and fetch from cookie
		cookie, err := r.Cookie(k.cookieOpts.Name)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				// kvSess.id = newSID()
				return nil, nil
			}
			return nil, fmt.Errorf("getting cookie %s: %w", k.cookieOpts.Name, err)
		}
		kvSess.id = cookie.Value
	}

	b, ok, err := k.kv.Get(r.Context(), k.storeID(kvSess.id))
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

	if err := k.kv.Set(r.Context(), k.storeID(kvSess.id), expiresAt, data); err != nil {
		return fmt.Errorf("putting session data: %w", err)
	}

	// TODO - check existing cookie/header, only set if changed (e.g expiry),
	// remove any delete.

	c := k.cookieOpts.newCookie()
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

	if err := k.kv.Delete(r.Context(), k.storeID(kvSess.id)); err != nil {
		return fmt.Errorf("deleting session %s from store: %w", kvSess.id, err)
	}

	// always clear the cookie
	dc := k.cookieOpts.newCookie()
	dc.MaxAge = -1
	http.SetCookie(w, dc)

	// assign a fresh SID, so if we do save again it'll go under a new session.
	// If not, it's ignored. This prevents a `Get` from trying to re-load from
	// the cookie.
	kvSess.id = newSID()

	return nil
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

func (k *kvStore) storeID(id string) string {
	h := sha256.New()
	h.Write([]byte(id))
	return hex.EncodeToString(h.Sum(nil))
}

type kvSessCtxKey struct{ inst *kvStore }

// kvSession tracks information about the session across the request's context
type kvSession struct {
	id string
}
