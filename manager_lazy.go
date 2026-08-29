package session

import (
	"crypto/rand"
	"log/slog"
	"net/http"
	"time"

	"lds.li/session/internal/dbscproof"
)

type sessionIDPeeker interface {
	peekSessionID(r *http.Request) bool
}

func (m *Manager[T]) isDBSCRegistrationRequest(r *http.Request) bool {
	return m.opts.DBSCRefreshInterval > 0 &&
		r.Method == http.MethodPost &&
		r.URL.Path == m.dbscRegistrationPath()
}

func (m *Manager[T]) isDBSCRefreshRequest(r *http.Request) bool {
	return m.opts.DBSCRefreshInterval > 0 &&
		r.Method == http.MethodPost &&
		r.URL.Path == m.dbscRefreshPath()
}

// ensureSessionLoaded loads persisted session state on first use. For lazy KV
// managers it also runs in-band DBSC enforcement. Returns true when the
// response has been handled and the request should not continue.
func (m *Manager[T]) ensureSessionLoaded(w http.ResponseWriter, r *http.Request, sctx *Session[T]) bool {
	if sctx.loadFailed {
		return true
	}
	if !m.lazyLoad {
		return sctx.aborted
	}
	if sctx.loaded {
		return sctx.aborted
	}

	data, found, err := m.loadSession(r)
	if err != nil {
		m.handleErr(w, r, err)
		sctx.loadFailed = true
		return true
	}
	if err := m.installLoadedSession(sctx, data, found); err != nil {
		m.handleErr(w, r, err)
		sctx.loadFailed = true
		return true
	}

	abort := false
	if m.opts.DBSCRefreshInterval > 0 && len(sctx.meta.DBSCPublicJWK) > 0 {
		abort = m.runDBSCInBand(w, r, sctx)
	}
	if abort {
		sctx.aborted = true
	}
	return abort
}

// rejectDBSCSkipped rejects requests where the client could not complete DBSC.
// Secure-Session-Skipped is a diagnostic header from the browser. It must
// not bypass device binding. Returns true when a 401 was written.
func (m *Manager[T]) rejectDBSCSkipped(w http.ResponseWriter, r *http.Request, sessionID string) bool {
	if !dbscSessionSkipped(r, sessionID) {
		return false
	}
	slog.WarnContext(r.Context(), "DBSC rejected: client sent Secure-Session-Skipped")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return true
}

// runDBSCInBand enforces device-bound session freshness. Returns true when a
// challenge or error response was written to w.
func (m *Manager[T]) runDBSCInBand(w http.ResponseWriter, r *http.Request, sctx *Session[T]) bool {
	if m.rejectDBSCSkipped(w, r, sctx.meta.DBSCSessionID) {
		return true
	}

	boundCookie, err := r.Cookie(m.dbscBoundCookieName())
	isBoundCookieValid := err == nil && boundCookie.Value != "" && boundCookie.Value == sctx.meta.DBSCCurrentCookieID

	isExpired := sctx.meta.DBSCExpiration.IsZero() || time.Now().After(sctx.meta.DBSCExpiration)
	if isBoundCookieValid && !isExpired {
		return false
	}

	respHeader := dbscSessionResponseHeader(r)
	if respHeader == "" {
		m.dbscIssueInBandChallenge(w, r, sctx)
		return true
	}

	now := time.Now()
	jti, err := dbscproof.VerifyRefresh(respHeader, registeredDBSCKey(sctx))
	if err != nil {
		slog.WarnContext(r.Context(), "DBSC verification failed", "err", err)
		m.dbscIssueInBandChallenge(w, r, sctx)
		return true
	}

	if err := verifyDBSCRefreshChallenge(sctx, jti, now); err != nil {
		slog.WarnContext(r.Context(), "DBSC challenge verification failed", "err", err)
		m.dbscIssueInBandChallenge(w, r, sctx)
		return true
	}

	consumeDBSCRefreshChallenge(sctx, jti, now)

	sctx.meta.DBSCExpiration = now.Add(m.opts.DBSCRefreshInterval)
	sctx.meta.DBSCCurrentCookieID = rand.Text()
	sctx.metaDirty = true
	return false
}
