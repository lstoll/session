package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// KV stores encoded server-side sessions. Implementations must be safe for
// concurrent use. Set must not retain value, and Get must return an independent
// byte slice. Expired entries must be reported as not found.
type KV interface {
	Get(_ context.Context, key string) (_ []byte, found bool, _ error)
	Set(_ context.Context, key string, expiresAt time.Time, value []byte) error
	Delete(_ context.Context, key string) error
}

type kvStore[T any] struct {
	m              *Manager[T]
	kv             KV
	cookieSettings SessionCookieOpts
	authenticator  Authenticator
}

const managerAuthenticatedSessionCookieMagic = "AS1"

func (s *kvStore[T]) sessionIDAuthenticatorInput(id string) []byte {
	return []byte(s.cookieSettings.Name + "\x00" + id)
}

//nolint:unused // Used by generic store methods. golangci-lint does not resolve the instantiation.
func (s *kvStore[T]) authenticateSessionID(id string) (string, error) {
	if s.authenticator == nil {
		return id, nil
	}
	tag, err := s.authenticator.Authenticate(s.sessionIDAuthenticatorInput(id))
	if err != nil {
		return "", fmt.Errorf("authenticating session id: %w", err)
	}
	return managerAuthenticatedSessionCookieMagic + "." + id + "." + managerCookieValueEncoding.EncodeToString(tag), nil
}

func (s *kvStore[T]) parseSessionIDCookie(raw string) (id string, ok bool) {
	if s.authenticator == nil {
		if !plausibleSessionID(raw) {
			return "", false
		}
		return raw, true
	}
	if len(raw) > managerMaxSetCookieSize {
		return "", false
	}
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 || parts[0] != managerAuthenticatedSessionCookieMagic || !plausibleSessionID(parts[1]) {
		return "", false
	}
	tag, err := managerCookieValueEncoding.DecodeString(parts[2])
	if err != nil || s.authenticator.Verify(s.sessionIDAuthenticatorInput(parts[1]), tag) != nil {
		return "", false
	}
	return parts[1], true
}

// plausibleSessionID bounds attacker-controlled KV lookup input. It does not
// authenticate the ID. Only a successful store lookup makes an ID reusable.
func plausibleSessionID(id string) bool {
	return id != "" && len(id) <= 128
}

func (s *kvStore[T]) peekSessionID(r *http.Request) bool {
	cookie, err := r.Cookie(s.cookieSettings.Name)
	if err != nil {
		return false
	}
	sessionID, ok := s.parseSessionIDCookie(cookie.Value)
	if !ok {
		return false
	}
	setManagerSessionIDInContext(r, s.m, sessionID)
	return true
}

//nolint:unused // Implements sessionStore. golangci-lint does not resolve the generic interface implementation.
func (s *kvStore[T]) load(r *http.Request) ([]byte, bool, error) {
	cookie, err := r.Cookie(s.cookieSettings.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("getting cookie %s: %w", s.cookieSettings.Name, err)
	}

	sessionID, ok := s.parseSessionIDCookie(cookie.Value)
	if !ok {
		return nil, false, nil
	}
	// A client-provided ID is only reusable after the store confirms that it was
	// issued by this server. Until then, a subsequent save must generate a new ID.
	setManagerSessionIDInContext(r, s.m, "")

	// Hash the session ID for storage
	storeKey := managerHashSessionID(sessionID)

	// Get data from KV
	data, found, err := s.kv.Get(r.Context(), storeKey)
	if err != nil {
		return nil, false, fmt.Errorf("getting from KV: %w", err)
	}

	if !found {
		return nil, false, nil
	}

	setManagerSessionIDInContext(r, s.m, sessionID)
	return data, true, nil
}

//nolint:unused // Implements sessionStore. golangci-lint does not resolve the generic interface implementation.
func (s *kvStore[T]) save(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error {
	// Generate or get session ID
	sessionID := getManagerSessionIDFromContext(r, s.m)
	if sessionID == "" {
		sessionID = rand.Text()
		setManagerSessionIDInContext(r, s.m, sessionID)
	}

	// Hash the session ID for storage
	storeKey := managerHashSessionID(sessionID)

	// Store in KV
	if err := s.kv.Set(r.Context(), storeKey, expiresAt, data); err != nil {
		return fmt.Errorf("storing in KV: %w", err)
	}

	return s.writeSessionCookie(w, expiresAt, sessionID)
}

//nolint:unused // Implements sessionStore. golangci-lint does not resolve the generic interface implementation.
func (s *kvStore[T]) delete(r *http.Request) error {
	sessionID := getManagerSessionIDFromContext(r, s.m)
	if sessionID == "" {
		// Try to get from cookie
		cookie, err := r.Cookie(s.cookieSettings.Name)
		if err == nil {
			if id, ok := s.parseSessionIDCookie(cookie.Value); ok {
				sessionID = id
			}
		}
	}

	if sessionID != "" {
		storeKey := managerHashSessionID(sessionID)
		if err := s.kv.Delete(r.Context(), storeKey); err != nil {
			return fmt.Errorf("deleting from KV: %w", err)
		}
	}

	// Generate a new ID for potential future use
	setManagerSessionIDInContext(r, s.m, rand.Text())

	return nil
}

//nolint:unused // Implements sessionStore. golangci-lint does not resolve the generic interface implementation.
func (s *kvStore[T]) touch(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error {
	// Get session ID
	sessionID := getManagerSessionIDFromContext(r, s.m)
	if sessionID == "" {
		cookie, err := r.Cookie(s.cookieSettings.Name)
		if err != nil {
			return nil // No session to touch
		}
		sessionID, ok := s.parseSessionIDCookie(cookie.Value)
		if !ok {
			return nil
		}
		setManagerSessionIDInContext(r, s.m, sessionID)
	}

	// Update KV expiry
	storeKey := managerHashSessionID(sessionID)
	if err := s.kv.Set(r.Context(), storeKey, expiresAt, data); err != nil {
		return fmt.Errorf("updating KV expiry: %w", err)
	}

	return s.writeSessionCookie(w, expiresAt, sessionID)
}

//nolint:unused // Used by generic store methods. golangci-lint does not resolve the instantiation.
func (s *kvStore[T]) writeSessionCookie(w http.ResponseWriter, expiresAt time.Time, sessionID string) error {
	cookieValue, err := s.authenticateSessionID(sessionID)
	if err != nil {
		return err
	}
	cookie := s.cookieSettings.newCookie(expiresAt)
	cookie.Value = cookieValue

	managerRemoveCookieByName(w, cookie.Name)
	return managerSetCookie(w, cookie)
}

// Generate a consistent hash of session ID for KV storage
func managerHashSessionID(id string) string {
	h := sha256.New()
	h.Write([]byte(id))
	return hex.EncodeToString(h.Sum(nil))
}
