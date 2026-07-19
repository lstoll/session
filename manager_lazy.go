package session

import (
	"crypto/rand"
	"log/slog"
	"net/http"
	"time"
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
	if !m.lazyLoad {
		return sctx.aborted
	}
	if sctx.loaded {
		return sctx.aborted
	}

	decodedData, data, err := m.loadSession(r)
	if err != nil {
		m.handleErr(w, r, err)
		sctx.aborted = true
		return true
	}
	m.installLoadedSession(sctx, decodedData, data)

	abort := false
	if m.opts.DBSCRefreshInterval > 0 && len(sctx.sessdata.DBSCPublicJWKS) > 0 {
		abort = m.runDBSCInBand(w, r, sctx)
	}
	if abort {
		sctx.aborted = true
	}
	return abort
}

// rejectDBSCSkipped rejects requests where the client could not complete DBSC.
// Sec-Secure-Session-Skipped is a diagnostic header from the browser; it must
// not bypass device binding. Returns true when a 401 was written.
func (m *Manager[T]) rejectDBSCSkipped(w http.ResponseWriter, r *http.Request) bool {
	if !dbscSessionSkipped(r) {
		return false
	}
	slog.WarnContext(r.Context(), "DBSC rejected: client sent Sec-Secure-Session-Skipped")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return true
}

// runDBSCInBand enforces device-bound session freshness. Returns true when a
// challenge or error response was written to w.
func (m *Manager[T]) runDBSCInBand(w http.ResponseWriter, r *http.Request, sctx *Session[T]) bool {
	if m.rejectDBSCSkipped(w, r) {
		return true
	}

	boundCookie, err := r.Cookie(m.dbscBoundCookieName())
	isBoundCookieValid := err == nil && boundCookie.Value != "" && boundCookie.Value == sctx.sessdata.DBSCCurrentCookieID

	isExpired := !sctx.sessdata.DBSCExpiration.IsZero() && time.Now().After(sctx.sessdata.DBSCExpiration)
	if isBoundCookieValid && !isExpired {
		return false
	}

	respHeader := dbscSessionResponseHeader(r)
	if respHeader == "" {
		m.dbscIssueInBandChallenge(w, r, sctx)
		return true
	}

	jti, err := extractDBSCProofJTI(respHeader)
	if err != nil {
		slog.WarnContext(r.Context(), "DBSC proof invalid format", "err", err)
		m.dbscIssueInBandChallenge(w, r, sctx)
		return true
	}

	if err := m.dbscStore.verifyChallenge(r, sctx, jti, false); err != nil {
		slog.WarnContext(r.Context(), "DBSC challenge verification failed", "err", err)
		m.dbscIssueInBandChallenge(w, r, sctx)
		return true
	}

	if err := verifyDBSCResponse(respHeader, sctx.sessdata.DBSCPublicJWKS, jti); err != nil {
		slog.WarnContext(r.Context(), "DBSC verification failed", "err", err)
		sctx.Delete()
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return true
	}
	if err := m.dbscStore.consumeChallenge(r, sctx, jti); err != nil {
		m.handleErr(w, r, err)
		return true
	}

	sctx.sessdata.DBSCExpiration = time.Now().Add(m.opts.DBSCRefreshInterval)
	sctx.sessdata.DBSCCurrentCookieID = rand.Text()
	sctx.Reset()
	return false
}
