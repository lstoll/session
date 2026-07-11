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

	"github.com/tink-crypto/tink-go/v2/tink"
)

type KV interface {
	Get(_ context.Context, key string) (_ []byte, found bool, _ error)
	Set(_ context.Context, key string, expiresAt time.Time, value []byte) error
	Delete(_ context.Context, key string) error
}

const managerMACSessionCookieMagic = "MS1"

type kvStore struct {
	m              *Manager
	kv             KV
	codec          codec
	cookieSettings SessionCookieOpts
	mac            tink.MAC
}

func (s *kvStore) sessionIDMACInput(id string) []byte {
	return []byte(s.cookieSettings.Name + ":" + id)
}

func (s *kvStore) signSessionID(id string) (string, error) {
	if s.mac == nil {
		return id, nil
	}
	tag, err := s.mac.ComputeMAC(s.sessionIDMACInput(id))
	if err != nil {
		return "", fmt.Errorf("signing session id: %w", err)
	}
	return managerMACSessionCookieMagic + "." + id + "." + managerCookieValueEncoding.EncodeToString(tag), nil
}

func (s *kvStore) parseSessionIDCookie(raw string) (id string, ok bool) {
	if s.mac == nil {
		if raw == "" {
			return "", false
		}
		return raw, true
	}
	sp := strings.SplitN(raw, ".", 3)
	if len(sp) != 3 || sp[0] != managerMACSessionCookieMagic || sp[1] == "" || sp[2] == "" {
		return "", false
	}
	tag, err := managerCookieValueEncoding.DecodeString(sp[2])
	if err != nil {
		return "", false
	}
	if err := s.mac.VerifyMAC(tag, s.sessionIDMACInput(sp[1])); err != nil {
		return "", false
	}
	return sp[1], true
}

func (s *kvStore) peekSessionID(r *http.Request) bool {
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

func (s *kvStore) load(r *http.Request) (persistedSession, []byte, error) {
	cookie, err := r.Cookie(s.cookieSettings.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return persistedSession{}, nil, nil
		}
		return persistedSession{}, nil, fmt.Errorf("getting cookie %s: %w", s.cookieSettings.Name, err)
	}

	sessionID, ok := s.parseSessionIDCookie(cookie.Value)
	if !ok {
		return persistedSession{}, nil, nil
	}
	setManagerSessionIDInContext(r, s.m, sessionID)

	// Hash the session ID for storage
	storeKey := managerHashSessionID(sessionID)

	// Get data from KV
	data, found, err := s.kv.Get(r.Context(), storeKey)
	if err != nil {
		return persistedSession{}, nil, fmt.Errorf("getting from KV: %w", err)
	}

	if !found {
		return persistedSession{}, nil, nil
	}

	// Decode using the codec
	sess, err := s.codec.Decode(data)
	if err != nil {
		return persistedSession{}, nil, fmt.Errorf("decoding session: %w", err)
	}

	return sess, data, nil
}

func (s *kvStore) save(w http.ResponseWriter, r *http.Request, expiresAt time.Time, sess persistedSession) error {
	// Generate or get session ID
	sessionID := getManagerSessionIDFromContext(r, s.m)
	if sessionID == "" {
		sessionID = rand.Text()
		setManagerSessionIDInContext(r, s.m, sessionID)
	}

	// Hash the session ID for storage
	storeKey := managerHashSessionID(sessionID)

	// Encode using the codec
	data, err := s.codec.Encode(sess)
	if err != nil {
		return fmt.Errorf("encoding session: %w", err)
	}

	// Store in KV
	if err := s.kv.Set(r.Context(), storeKey, expiresAt, data); err != nil {
		return fmt.Errorf("storing in KV: %w", err)
	}

	// Set session ID cookie
	cookieValue, err := s.signSessionID(sessionID)
	if err != nil {
		return err
	}
	cookie := s.cookieSettings.newCookie(expiresAt)
	cookie.Value = cookieValue

	managerRemoveCookieByName(w, cookie.Name)
	http.SetCookie(w, cookie)

	return nil
}

func (s *kvStore) delete(w http.ResponseWriter, r *http.Request) error {
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

func (s *kvStore) touch(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error {
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

	// Update cookie expiry
	cookieValue, err := s.signSessionID(sessionID)
	if err != nil {
		return err
	}
	cookie := s.cookieSettings.newCookie(expiresAt)
	cookie.Value = cookieValue

	managerRemoveCookieByName(w, cookie.Name)
	http.SetCookie(w, cookie)

	return nil
}

func (s *kvStore) generateChallenge(r *http.Request, sctx *Session, isRegister bool) (string, error) {
	challenge := rand.Text()
	sctx.sessdataMu.Lock()
	if isRegister {
		sctx.sessdata.DBSCRegistrationChallenge = challenge
	} else {
		sctx.sessdata.DBSCChallenge = challenge
		sctx.sessdata.DBSCChallengeIssuedAt = time.Now()
	}
	sctx.save = true
	sctx.sessdataMu.Unlock()
	return challenge, nil
}

func (s *kvStore) verifyChallenge(r *http.Request, sctx *Session, challengeStr string, isRegister bool) error {
	sctx.sessdataMu.RLock()
	defer sctx.sessdataMu.RUnlock()
	if isRegister {
		if sctx.sessdata.DBSCRegistrationChallenge == "" || sctx.sessdata.DBSCRegistrationChallenge != challengeStr {
			return errors.New("registration challenge mismatch or missing")
		}
	} else {
		if sctx.sessdata.DBSCChallenge == "" || sctx.sessdata.DBSCChallenge != challengeStr {
			return errors.New("refresh challenge mismatch or missing")
		}
		if sctx.sessdata.DBSCChallengeIssuedAt.IsZero() || time.Since(sctx.sessdata.DBSCChallengeIssuedAt) > 5*time.Minute {
			return errors.New("refresh challenge expired")
		}
	}
	return nil
}

// Generate a consistent hash of session ID for KV storage
func managerHashSessionID(id string) string {
	h := sha256.New()
	h.Write([]byte(id))
	return hex.EncodeToString(h.Sum(nil))
}
