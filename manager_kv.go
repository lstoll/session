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

type kvStore[T any] struct {
	m              *Manager[T]
	kv             KV
	codec          codec[T]
	cookieSettings SessionCookieOpts
	mac            tink.MAC
}

func (s *kvStore[T]) sessionIDMACInput(id string) []byte {
	return []byte(s.cookieSettings.Name + ":" + id)
}

func (s *kvStore[T]) signSessionID(id string) (string, error) {
	if s.mac == nil {
		return id, nil
	}
	tag, err := s.mac.ComputeMAC(s.sessionIDMACInput(id))
	if err != nil {
		return "", fmt.Errorf("signing session id: %w", err)
	}
	return managerMACSessionCookieMagic + "." + id + "." + managerCookieValueEncoding.EncodeToString(tag), nil
}

func (s *kvStore[T]) parseSessionIDCookie(raw string) (id string, ok bool) {
	if s.mac == nil {
		if !plausibleSessionID(raw) {
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

// plausibleSessionID bounds attacker-controlled KV lookup input. It does not
// authenticate the ID; only a successful store lookup makes an ID reusable.
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

func (s *kvStore[T]) load(r *http.Request) (persistedSession[T], []byte, error) {
	cookie, err := r.Cookie(s.cookieSettings.Name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return persistedSession[T]{}, nil, nil
		}
		return persistedSession[T]{}, nil, fmt.Errorf("getting cookie %s: %w", s.cookieSettings.Name, err)
	}

	sessionID, ok := s.parseSessionIDCookie(cookie.Value)
	if !ok {
		return persistedSession[T]{}, nil, nil
	}
	// A client-provided ID is only reusable after the store confirms that it was
	// issued by this server. Until then, a subsequent save must generate a new ID.
	setManagerSessionIDInContext(r, s.m, "")

	// Hash the session ID for storage
	storeKey := managerHashSessionID(sessionID)

	// Get data from KV
	data, found, err := s.kv.Get(r.Context(), storeKey)
	if err != nil {
		return persistedSession[T]{}, nil, fmt.Errorf("getting from KV: %w", err)
	}

	if !found {
		return persistedSession[T]{}, nil, nil
	}

	// Decode using the codec
	sess, err := s.codec.Decode(data)
	if err != nil {
		return persistedSession[T]{}, nil, fmt.Errorf("decoding session: %w", err)
	}
	setManagerSessionIDInContext(r, s.m, sessionID)

	return sess, data, nil
}

func (s *kvStore[T]) save(w http.ResponseWriter, r *http.Request, expiresAt time.Time, sess persistedSession[T]) error {
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

	return s.writeSessionCookie(w, expiresAt, sessionID)
}

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

func (s *kvStore[T]) writeSessionCookie(w http.ResponseWriter, expiresAt time.Time, sessionID string) error {
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

func (s *kvStore[T]) generateChallenge(r *http.Request, sctx *Session[T], isRegister bool) (string, error) {
	challenge := rand.Text()
	if isRegister {
		sctx.sessdata.DBSCRegistrationChallenge = challenge
		sctx.state = sessionDirty
		return challenge, nil
	}

	sessionID := sctx.sessdata.DBSCSessionID
	if sessionID == "" {
		return "", errors.New("cannot issue refresh challenge without DBSC session ID")
	}
	if err := s.kv.Set(r.Context(), dbscChallengeKey(sessionID, challenge), time.Now().Add(dbscProofMaxAge), []byte{1}); err != nil {
		return "", fmt.Errorf("storing DBSC challenge: %w", err)
	}
	return challenge, nil
}

func (s *kvStore[T]) verifyChallenge(r *http.Request, sctx *Session[T], challengeStr string, isRegister bool) error {
	if isRegister {
		if sctx.sessdata.DBSCRegistrationChallenge == "" || sctx.sessdata.DBSCRegistrationChallenge != challengeStr {
			return errors.New("registration challenge mismatch or missing")
		}
		return nil
	}
	sessionID := sctx.sessdata.DBSCSessionID
	legacyChallenge := sctx.sessdata.DBSCChallenge
	legacyIssuedAt := sctx.sessdata.DBSCChallengeIssuedAt

	data, found, err := s.kv.Get(r.Context(), dbscChallengeKey(sessionID, challengeStr))
	if err != nil {
		return fmt.Errorf("loading DBSC challenge: %w", err)
	}
	if found && len(data) == 1 && data[0] == 1 {
		return nil
	}
	// Accept one challenge persisted by versions before independent challenge
	// records were introduced, so in-flight upgrades do not break refreshes.
	if legacyChallenge == challengeStr && !legacyIssuedAt.IsZero() && time.Since(legacyIssuedAt) <= dbscProofMaxAge {
		return nil
	}
	return errors.New("refresh challenge mismatch, missing, or expired")
}

func (s *kvStore[T]) consumeChallenge(r *http.Request, sctx *Session[T], challengeStr string) error {
	sessionID := sctx.sessdata.DBSCSessionID
	if sctx.sessdata.DBSCChallenge == challengeStr {
		sctx.sessdata.DBSCChallenge = ""
		sctx.sessdata.DBSCChallengeIssuedAt = time.Time{}
		sctx.state = sessionDirty
	}
	if err := s.kv.Delete(r.Context(), dbscChallengeKey(sessionID, challengeStr)); err != nil {
		return fmt.Errorf("consuming DBSC challenge: %w", err)
	}
	return nil
}

func dbscChallengeKey(sessionID, challenge string) string {
	return managerHashSessionID("dbsc-challenge:" + sessionID + ":" + challenge)
}

// Generate a consistent hash of session ID for KV storage
func managerHashSessionID(id string) string {
	h := sha256.New()
	h.Write([]byte(id))
	return hex.EncodeToString(h.Sum(nil))
}
