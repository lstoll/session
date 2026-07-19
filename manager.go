package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go/v2/tink"
)

// FromContext returns the Session this Manager stored in ctx.
// It panics if this Manager did not install a session in ctx.
func (m *Manager[T]) FromContext(ctx context.Context) *Session[T] {
	sess, ok := ctx.Value(sessionContextKey[T]{manager: m}).(*Session[T])
	if !ok {
		panic("no session in context for this Manager")
	}
	return sess
}

type sessionStore[T any] interface {
	load(r *http.Request) (persistedSession[T], []byte, error)
	save(w http.ResponseWriter, r *http.Request, expiresAt time.Time, sess persistedSession[T]) error
	delete(r *http.Request) error
	touch(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error
}

type dbscChallengeStore[T any] interface {
	generateChallenge(r *http.Request, sctx *Session[T], isRegister bool) (string, error)
	verifyChallenge(r *http.Request, sctx *Session[T], challengeStr string, isRegister bool) error
	consumeChallenge(r *http.Request, sctx *Session[T], challengeStr string) error
}

// Manager handles both session data and storage.
type Manager[T any] struct {
	store          sessionStore[T]
	dbscStore      dbscChallengeStore[T]
	cookieSettings SessionCookieOpts
	codec          codec[T]
	opts           managerOpts[T]
	lazyLoad       bool
}

var DefaultIdleTimeout = 24 * time.Hour

// SessionCookieOpts configures cookie behavior for sessions
type SessionCookieOpts struct {
	Name     string
	Path     string
	Insecure bool
	Persist  bool
}

// newCookie creates a cookie with the configured options
func (c *SessionCookieOpts) newCookie(exp time.Time) *http.Cookie {
	hc := &http.Cookie{
		Name:     c.Name,
		Path:     c.Path,
		Secure:   !c.Insecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if c.Persist {
		hc.MaxAge = int(time.Until(exp).Seconds())
	}
	return hc
}

type managerOpts[T any] struct {
	MaxLifetime  time.Duration
	IdleTimeout  time.Duration
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
	Onload       func(T) T
	CookieOpts   *SessionCookieOpts

	DBSCRefreshInterval  time.Duration
	DBSCRegistrationPath string
	DBSCRefreshPath      string
	DBSCOrigin           string
}

// CookieManagerOpts configures options specifically for the cookie-based session manager
type CookieManagerOpts[T any] struct {
	MaxLifetime time.Duration
	IdleTimeout time.Duration
	// ErrorHandler handles failures that prevent the manager from safely loading
	// or persisting session state. When nil, the manager logs the error and
	// responds 500.
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
	// Onload is called when a session is retrieved from storage.
	Onload func(T) T
	// Cookie settings.
	CookieOpts         *SessionCookieOpts
	DisableCompression bool
}

// KVManagerOpts configures options specifically for the KV-based session manager
type KVManagerOpts[T any] struct {
	MaxLifetime time.Duration
	IdleTimeout time.Duration
	// ErrorHandler handles failures that prevent the manager from safely loading
	// or persisting session state. Eager load failures prevent the application
	// handler from running. Lazy load failures are discovered by the first session
	// accessor; the session and response are then aborted. When nil, the manager
	// logs the error and responds 500.
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
	// Onload is called when a session is retrieved from storage.
	Onload func(T) T
	// Cookie settings.
	CookieOpts *SessionCookieOpts

	// SessionIDMAC authenticates the opaque session ID cookie value. When set,
	// clients cannot forge session IDs to provoke arbitrary KV lookups or writes.
	SessionIDMAC tink.MAC
	// EagerLoad loads session data from the KV store on every request. The default
	// is lazy loading: peek the session cookie up front and defer the KV Get until
	// the handler (or a DBSC endpoint) actually needs session state.
	EagerLoad bool

	// DBSCRefreshInterval defines how often the device must prove possession
	// of its private key. If 0, DBSC is disabled. Typical values are 5-15 minutes.
	DBSCRefreshInterval time.Duration
	// DBSCRegistrationPath is the URL path where the browser POSTs the registration
	// proof (Secure-Session-Response). When non-empty and DBSCRefreshInterval is set,
	// the manager handles POSTs to this path and responds with JSON session
	// instructions; your mux does not need a separate registration handler.
	// Secure-Session-Registration is also emitted automatically when a response
	// saves session data (see Session.InitiateDBSCRegistration for edge cases).
	DBSCRegistrationPath string
	// DBSCRefreshPath is the refresh_url placed in session instructions. Defaults
	// to "/dbsc/refresh" if empty. POSTs to this path are handled by the manager.
	DBSCRefreshPath string
	// DBSCOrigin is the origin sent in DBSC session instructions (scope.origin),
	// e.g. "https://example.com". Required when DBSCRefreshInterval is set.
	DBSCOrigin string
}

// NewCookieManager creates a new Manager that stores session data in cookies
func NewCookieManager[T any](aead tink.AEAD, opts *CookieManagerOpts[T]) (*Manager[T], error) {
	normalized, compressionDisabled := normalizeCookieManagerOpts(opts)
	m := &Manager[T]{
		opts:  normalized,
		codec: &gobCodec[T]{},
	}

	if m.opts.IdleTimeout == 0 && m.opts.MaxLifetime == 0 {
		return nil, errors.New("at least one of idle timeout or max lifetime must be specified")
	}
	// Set cookie options
	if m.opts.CookieOpts != nil {
		m.cookieSettings = *m.opts.CookieOpts
	} else {
		m.cookieSettings = SessionCookieOpts{
			Name: "__Host-session",
			Path: "/",
		}
	}

	m.store = &cookieStore[T]{
		aead:                aead,
		codec:               m.codec,
		compressionDisabled: compressionDisabled,
		cookieSettings:      m.cookieSettings,
	}

	return m, nil
}

// NewKVManager creates a new Manager that stores session data in a KV store
func NewKVManager[T any](kv KV, opts *KVManagerOpts[T]) (*Manager[T], error) {
	normalized, sessionIDMAC, eagerLoad := normalizeKVManagerOpts(opts)
	m := &Manager[T]{
		opts:  normalized,
		codec: &gobCodec[T]{},
	}

	if m.opts.IdleTimeout == 0 && m.opts.MaxLifetime == 0 {
		return nil, errors.New("at least one of idle timeout or max lifetime must be specified")
	}
	if err := validateDBSCOpts(m.opts); err != nil {
		return nil, err
	}

	// Set cookie options
	if m.opts.CookieOpts != nil {
		m.cookieSettings = *m.opts.CookieOpts
	} else {
		m.cookieSettings = SessionCookieOpts{
			Name: "__Host-session-id",
			Path: "/",
		}
	}

	store := &kvStore[T]{
		m:              m,
		kv:             kv,
		codec:          m.codec,
		cookieSettings: m.cookieSettings,
		mac:            sessionIDMAC,
	}
	m.store = store
	m.dbscStore = store

	m.lazyLoad = !eagerLoad

	return m, nil
}

func normalizeCookieManagerOpts[T any](opts *CookieManagerOpts[T]) (managerOpts[T], bool) {
	if opts == nil {
		return managerOpts[T]{IdleTimeout: DefaultIdleTimeout}, false
	}
	normalized := managerOpts[T]{
		MaxLifetime:  opts.MaxLifetime,
		IdleTimeout:  opts.IdleTimeout,
		ErrorHandler: opts.ErrorHandler,
		Onload:       opts.Onload,
		CookieOpts:   opts.CookieOpts,
	}
	if normalized.IdleTimeout == 0 && normalized.MaxLifetime == 0 {
		normalized.IdleTimeout = DefaultIdleTimeout
	}
	return normalized, opts.DisableCompression
}

func normalizeKVManagerOpts[T any](opts *KVManagerOpts[T]) (managerOpts[T], tink.MAC, bool) {
	if opts == nil {
		return managerOpts[T]{IdleTimeout: DefaultIdleTimeout}, nil, false
	}
	normalized := managerOpts[T]{
		MaxLifetime:          opts.MaxLifetime,
		IdleTimeout:          opts.IdleTimeout,
		ErrorHandler:         opts.ErrorHandler,
		Onload:               opts.Onload,
		CookieOpts:           opts.CookieOpts,
		DBSCRefreshInterval:  opts.DBSCRefreshInterval,
		DBSCRegistrationPath: opts.DBSCRegistrationPath,
		DBSCRefreshPath:      opts.DBSCRefreshPath,
		DBSCOrigin:           opts.DBSCOrigin,
	}
	if normalized.IdleTimeout == 0 && normalized.MaxLifetime == 0 {
		normalized.IdleTimeout = DefaultIdleTimeout
	}
	return normalized, opts.SessionIDMAC, opts.EagerLoad
}

func validateDBSCOpts[T any](opts managerOpts[T]) error {
	if opts.DBSCRefreshInterval == 0 {
		return nil
	}
	if opts.DBSCOrigin == "" {
		return errors.New("DBSCOrigin is required when DBSCRefreshInterval is set")
	}
	return nil
}

// Constants for cookie format in the Manager
const (
	managerCookieMagic           = "EU1"
	managerCompressedCookieMagic = "EC1"
	managerCompressThreshold     = 512
	managerMaxCookieSize         = 4096
)

var managerCookieValueEncoding = base64.RawURLEncoding

// Wrap creates middleware that handles session management for each request
func (m *Manager[T]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(sessionContextKey[T]{manager: m}).(*Session[T]); ok {
			panic("session middleware wrapped more than once for this Manager")
		}

		// Create new session context with initial metadata
		sctx := &Session[T]{
			mgr:   m,
			isNew: true,
			sessdata: persistedSession[T]{
				CreatedAt: time.Now(),
			},
		}

		if m.lazyLoad {
			if peeker, ok := m.store.(sessionIDPeeker); ok {
				peeker.peekSessionID(r)
			}
		} else {
			decodedData, data, err := m.loadSession(r)
			if err != nil {
				m.handleErr(w, r, err)
				return
			}
			m.installLoadedSession(sctx, decodedData, data)
		}

		dbscEnabled := m.opts.DBSCRefreshInterval > 0

		hw := &hookRW{
			ResponseWriter: w,
			hook:           m.saveHook(r, sctx),
			aborted:        func() bool { return sctx.aborted },
		}
		sctx.reqW = hw
		sctx.reqR = r

		if dbscEnabled && m.isDBSCRegistrationRequest(r) {
			if m.ensureSessionLoaded(hw, r, sctx) {
				return
			}
			if m.tryHandleDBSCRegistration(hw, r, sctx) {
				return
			}
		}

		if dbscEnabled && m.isDBSCRefreshRequest(r) {
			if m.ensureSessionLoaded(hw, r, sctx) {
				return
			}
			if m.tryHandleDBSCRefresh(hw, r, sctx) {
				return
			}
		}

		if dbscEnabled && !m.lazyLoad && len(sctx.sessdata.DBSCPublicJWKS) > 0 {
			if m.runDBSCInBand(hw, r, sctx) {
				return
			}
		}

		ctx := context.WithValue(r.Context(), sessionContextKey[T]{manager: m}, sctx)
		if dbscEnabled {
			ctx = context.WithValue(ctx, dbscServeConfigKey{}, dbscServeConfig[T]{
				RegistrationPath:  m.dbscRegistrationPath(),
				GenerateChallenge: m.dbscStore.generateChallenge,
			})
		}
		r = r.WithContext(ctx)

		next.ServeHTTP(hw, r)

		// if the handler doesn't write anything, make sure we fire the hook
		// anyway.
		_ = hw.beforeWrite()
	})
}

// Storage methods

// loadSession retrieves session data from the appropriate storage
func (m *Manager[T]) loadSession(r *http.Request) (persistedSession[T], []byte, error) {
	return m.store.load(r)
}

func (m *Manager[T]) installLoadedSession(sctx *Session[T], decoded persistedSession[T], data []byte) {
	if data != nil {
		sctx.sessdata = decoded
		sctx.isNew = false
		if m.opts.IdleTimeout != 0 {
			sctx.loadedData = data
		}
		if m.opts.Onload != nil {
			sctx.sessdata.Data = m.opts.Onload(sctx.sessdata.Data)
		}
	}
	sctx.loaded = true
}

func (m *Manager[T]) saveHook(r *http.Request, sctx *Session[T]) func(w http.ResponseWriter) bool {
	return func(w http.ResponseWriter) bool {
		if sctx.state == sessionDeleted {
			if err := m.deleteSession(w, r, sctx); err != nil {
				m.handleErr(w, r, err)
				return false
			}
			return true
		}

		if sctx.rotate {
			if err := m.deleteSession(w, r, sctx); err != nil {
				m.handleErr(w, r, err)
				return false
			}
		}

		if sctx.state == sessionDirty {
			sctx.sessdata.UpdatedAt = time.Now()
			// DBSC registration is a response header; this hook runs before the first
			// Write/WriteHeader reaches the client, so we can still add it here.
			if !sctx.rotate {
				m.maybeAttachDBSCRegistrationOffer(w, r, sctx)
			}
			if err := m.saveSession(w, r, sctx); err != nil {
				m.handleErr(w, r, err)
				return false
			}
		} else if m.opts.IdleTimeout != 0 && sctx.loaded && len(sctx.loadedData) != 0 {
			// Just touch the session to update its lifetime
			if err := m.touchSession(w, r, sctx); err != nil {
				m.handleErr(w, r, err)
				return false
			}
		}

		return true
	}
}

// saveSession saves the session data to the appropriate storage
func (m *Manager[T]) saveSession(w http.ResponseWriter, r *http.Request, sctx *Session[T]) error {
	// If device-bound and DBSCCurrentCookieID is empty, generate one
	if len(sctx.sessdata.DBSCPublicJWKS) > 0 && sctx.sessdata.DBSCCurrentCookieID == "" {
		sctx.sessdata.DBSCCurrentCookieID = rand.Text()
	}

	// Calculate expiry
	expiresAt := m.calculateExpiry(sctx.sessdata)

	// Set DBSC bound cookie if device-bound
	m.setDBSCBoundCookie(w, sctx)

	return m.store.save(w, r, expiresAt, sctx.sessdata)
}

// deleteSession deletes the session from the appropriate storage
func (m *Manager[T]) deleteSession(w http.ResponseWriter, r *http.Request, sctx *Session[T]) error {
	// Delete cookie regardless of storage mode
	dc := m.cookieSettings.newCookie(time.Time{})
	dc.MaxAge = -1
	managerRemoveCookieByName(w, dc.Name)
	http.SetCookie(w, dc)

	// Also delete the DBSC bound cookie
	m.deleteDBSCBoundCookie(w)

	return m.store.delete(r)
}

// touchSession updates the session expiry without modifying content
func (m *Manager[T]) touchSession(w http.ResponseWriter, r *http.Request, sctx *Session[T]) error {
	expiresAt := m.calculateExpiry(sctx.sessdata)
	return m.store.touch(w, r, expiresAt, sctx.loadedData)
}

func (m *Manager[T]) calculateExpiry(sessdata persistedSession[T]) time.Time {
	var invalidTimes []time.Time

	if m.opts.MaxLifetime != 0 {
		maxInvalidAt := sessdata.CreatedAt.Add(m.opts.MaxLifetime)
		invalidTimes = append(invalidTimes, maxInvalidAt)
	}

	if m.opts.IdleTimeout != 0 {
		var idleInvalidAt time.Time
		if !sessdata.UpdatedAt.IsZero() {
			idleInvalidAt = sessdata.UpdatedAt.Add(m.opts.IdleTimeout)
		} else {
			idleInvalidAt = sessdata.CreatedAt.Add(m.opts.IdleTimeout)
		}
		invalidTimes = append(invalidTimes, idleInvalidAt)
	}

	if len(invalidTimes) == 0 {
		return time.Time{}
	}

	earliestInvalidAt := invalidTimes[0]
	for _, t := range invalidTimes[1:] {
		if t.Before(earliestInvalidAt) {
			earliestInvalidAt = t
		}
	}

	return earliestInvalidAt
}

// Helper functions for tracking KV-mode session ID in context
type managerSessionIDCtxKey[T any] struct{ manager *Manager[T] }

func getManagerSessionIDFromContext[T any](r *http.Request, m *Manager[T]) string {
	val := r.Context().Value(managerSessionIDCtxKey[T]{manager: m})
	if val == nil {
		return ""
	}
	return val.(string)
}

func setManagerSessionIDInContext[T any](r *http.Request, m *Manager[T], id string) {
	*r = *r.WithContext(context.WithValue(r.Context(), managerSessionIDCtxKey[T]{manager: m}, id))
}

// Cookie handling helper
func managerRemoveCookieByName(w http.ResponseWriter, cookieName string) {
	headers := w.Header()
	setCookieHeaders := w.Header()["Set-Cookie"]

	if len(setCookieHeaders) == 0 {
		return
	}

	updatedCookies := []string{}
	for _, cookie := range setCookieHeaders {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) > 0 && parts[0] != cookieName {
			updatedCookies = append(updatedCookies, cookie)
		}
	}

	headers.Del("Set-Cookie")
	for _, cookie := range updatedCookies {
		headers.Add("Set-Cookie", cookie)
	}
}

// maybeAttachDBSCRegistrationOffer sets Secure-Session-Registration when the
// session is being persisted, DBSC is configured, the session is not yet device
// bound, and there is no pending registration challenge. This is only called
// for a dirty session, so anonymous read-only hits do not trigger registration.
func (m *Manager[T]) maybeAttachDBSCRegistrationOffer(w http.ResponseWriter, r *http.Request, sctx *Session[T]) {
	if m.opts.DBSCRefreshInterval == 0 {
		slog.DebugContext(r.Context(), "dbsc registration offer skipped", "reason", "dbsc_not_configured")
		return
	}
	if len(sctx.sessdata.DBSCPublicJWKS) != 0 {
		slog.DebugContext(r.Context(), "dbsc registration offer skipped", "reason", "already_device_bound")
		return
	}
	if sctx.sessdata.DBSCRegistrationChallenge != "" {
		slog.DebugContext(r.Context(), "dbsc registration offer skipped", "reason", "challenge_already_pending")
		return
	}

	challenge, err := m.dbscStore.generateChallenge(r, sctx, true)
	if err != nil {
		slog.ErrorContext(r.Context(), "failed to generate registration challenge", "error", err)
		return
	}

	w.Header().Add("Secure-Session-Registration", `(ES256);path="`+m.dbscRegistrationPath()+`";challenge="`+challenge+`"`)
	slog.DebugContext(r.Context(), "dbsc registration offer attached",
		"registration_path", m.dbscRegistrationPath(),
		"challenge_len", len(challenge))
}

func (m *Manager[T]) dbscBoundCookieName() string {
	return m.cookieSettings.Name + "-bound"
}

func (m *Manager[T]) setDBSCBoundCookie(w http.ResponseWriter, sctx *Session[T]) {
	if len(sctx.sessdata.DBSCPublicJWKS) == 0 {
		return
	}
	// If DBSCCurrentCookieID is empty, generate one
	if sctx.sessdata.DBSCCurrentCookieID == "" {
		sctx.sessdata.DBSCCurrentCookieID = rand.Text()
	}

	hc := &http.Cookie{
		Name:     m.dbscBoundCookieName(),
		Value:    sctx.sessdata.DBSCCurrentCookieID,
		Path:     m.cookieSettings.Path,
		Secure:   !m.cookieSettings.Insecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	switch {
	case !sctx.sessdata.DBSCExpiration.IsZero():
		hc.MaxAge = int(time.Until(sctx.sessdata.DBSCExpiration).Seconds())
	case m.opts.DBSCRefreshInterval > 0:
		hc.MaxAge = int(m.opts.DBSCRefreshInterval.Seconds())
	}
	managerRemoveCookieByName(w, hc.Name)
	http.SetCookie(w, hc)
}

func (m *Manager[T]) deleteDBSCBoundCookie(w http.ResponseWriter) {
	dc := &http.Cookie{
		Name:     m.dbscBoundCookieName(),
		Path:     m.cookieSettings.Path,
		Secure:   !m.cookieSettings.Insecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	managerRemoveCookieByName(w, dc.Name)
	http.SetCookie(w, dc)
}

func (m *Manager[T]) dbscRefreshPath() string {
	if m.opts.DBSCRefreshPath != "" {
		return m.opts.DBSCRefreshPath
	}
	return "/dbsc/refresh"
}

func (m *Manager[T]) dbscRegistrationPath() string {
	if m.opts.DBSCRegistrationPath != "" {
		return m.opts.DBSCRegistrationPath
	}
	return "/dbsc/register"
}

func (m *Manager[T]) dbscCookieCredentialAttributes() string {
	var b strings.Builder
	if p := m.cookieSettings.Path; p != "" {
		b.WriteString("Path=")
		b.WriteString(p)
		b.WriteString("; ")
	}
	b.WriteString("HttpOnly")
	if !m.cookieSettings.Insecure {
		b.WriteString("; Secure")
	}
	b.WriteString("; SameSite=Lax")
	return b.String()
}

// dbscWriteInstructions sets headers, writes the JSON body, and logs warnings.
func (m *Manager[T]) dbscWriteInstructions(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		slog.WarnContext(r.Context(), "write DBSC instructions body", "err", err)
	}
}

func (m *Manager[T]) dbscRegistrationInstructions(sessionID string) ([]byte, error) {
	instructions := map[string]any{
		"session_identifier": sessionID,
		"refresh_url":        m.dbscRefreshPath(),
		"scope": map[string]any{
			"origin":              m.opts.DBSCOrigin,
			"include_site":        false,
			"scope_specification": []any{},
		},
		"credentials": []map[string]string{{
			"type":       "cookie",
			"name":       m.dbscBoundCookieName(),
			"attributes": m.dbscCookieCredentialAttributes(),
		}},
	}
	return json.Marshal(instructions)
}

// tryHandleDBSCRegistration handles POST DBSC registration proofs before the wrapped handler runs.
func (m *Manager[T]) tryHandleDBSCRegistration(w http.ResponseWriter, r *http.Request, sctx *Session[T]) bool {
	if m.opts.DBSCRefreshInterval == 0 {
		return false
	}
	if r.Method != http.MethodPost || r.URL.Path != m.dbscRegistrationPath() {
		return false
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "Cross-site registration rejected", http.StatusForbidden)
		return true
	}
	slog.DebugContext(r.Context(), "dbsc registration handler considering request",
		"method", r.Method, "path", r.URL.Path,
		"has_jwks", len(sctx.sessdata.DBSCPublicJWKS) > 0)
	if len(sctx.sessdata.DBSCPublicJWKS) != 0 {
		slog.DebugContext(r.Context(), "dbsc registration POST not handled", "reason", "already_bound")
		return false
	}

	tok := dbscSessionResponseHeader(r)
	if tok == "" {
		slog.DebugContext(r.Context(), "dbsc registration POST rejected", "reason", "missing_secure_session_response")
		http.Error(w, "missing Secure-Session-Response", http.StatusBadRequest)
		return true
	}
	slog.DebugContext(r.Context(), "dbsc registration verifying proof", "header_len", len(tok))

	jti, err := extractDBSCProofJTI(tok)
	if err != nil {
		slog.WarnContext(r.Context(), "DBSC registration proof invalid format", "err", err)
		http.Error(w, "invalid registration proof", http.StatusUnauthorized)
		return true
	}

	if err := m.dbscStore.verifyChallenge(r, sctx, jti, true); err != nil {
		slog.WarnContext(r.Context(), "DBSC registration challenge verification failed", "err", err)
		http.Error(w, "invalid registration proof", http.StatusUnauthorized)
		return true
	}

	jwks, err := verifyDBSCRegistrationProofAndJWKS(r.Context(), tok, jti)
	if err != nil {
		slog.WarnContext(r.Context(), "DBSC registration proof rejected", "err", err)
		http.Error(w, "invalid registration proof", http.StatusUnauthorized)
		return true
	}

	sessionID := deriveDBSCSessionID(jwks)

	sctx.sessdata.DBSCRegistrationChallenge = ""
	sctx.sessdata.DBSCPublicJWKS = jwks
	sctx.sessdata.DBSCSessionID = sessionID
	sctx.sessdata.DBSCExpiration = time.Now().Add(m.opts.DBSCRefreshInterval)
	sctx.state = sessionDirty

	body, err := m.dbscRegistrationInstructions(sessionID)
	if err != nil {
		m.handleErr(w, r, err)
		return true
	}
	m.dbscWriteInstructions(w, r, body)
	slog.DebugContext(r.Context(), "dbsc registration completed",
		"session_identifier_len", len(sessionID),
		"instructions_len", len(body))
	return true
}

// tryHandleDBSCRefresh handles POST DBSC refresh proofs per §5 / §8.8 of the spec.
func (m *Manager[T]) tryHandleDBSCRefresh(w http.ResponseWriter, r *http.Request, sctx *Session[T]) bool {
	if m.opts.DBSCRefreshInterval == 0 {
		return false
	}
	if r.Method != http.MethodPost || r.URL.Path != m.dbscRefreshPath() {
		return false
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "Cross-site refresh rejected", http.StatusForbidden)
		return true
	}
	if len(sctx.sessdata.DBSCPublicJWKS) == 0 {
		http.Error(w, "session not device-bound", http.StatusUnauthorized)
		return true
	}
	if m.rejectDBSCSkipped(w, r) {
		return true
	}

	sessionID := stripSFString(r.Header.Get("Sec-Secure-Session-Id"))
	if sessionID == "" || sessionID != sctx.sessdata.DBSCSessionID {
		http.Error(w, "invalid Sec-Secure-Session-Id", http.StatusUnauthorized)
		return true
	}

	tok := dbscSessionResponseHeader(r)
	if tok == "" {
		return m.dbscIssueRefreshChallenge(w, r, sctx)
	}

	jti, err := extractDBSCProofJTI(tok)
	if err != nil {
		slog.WarnContext(r.Context(), "DBSC refresh proof invalid format", "err", err)
		return m.dbscIssueRefreshChallenge(w, r, sctx)
	}

	if err := m.dbscStore.verifyChallenge(r, sctx, jti, false); err != nil {
		slog.WarnContext(r.Context(), "DBSC refresh challenge verification failed", "err", err)
		return m.dbscIssueRefreshChallenge(w, r, sctx)
	}

	if err := verifyDBSCResponse(tok, sctx.sessdata.DBSCPublicJWKS, jti); err != nil {
		slog.WarnContext(r.Context(), "DBSC refresh proof rejected", "err", err)
		http.Error(w, "invalid refresh proof", http.StatusUnauthorized)
		return true
	}
	if err := m.dbscStore.consumeChallenge(r, sctx, jti); err != nil {
		m.handleErr(w, r, err)
		return true
	}

	sctx.sessdata.DBSCExpiration = time.Now().Add(m.opts.DBSCRefreshInterval)

	// Generate new bound cookie value to rotate it
	sctx.sessdata.DBSCCurrentCookieID = rand.Text()

	sctx.state = sessionDirty

	body, err := m.dbscRegistrationInstructions(sctx.sessdata.DBSCSessionID)
	if err != nil {
		m.handleErr(w, r, err)
		return true
	}
	m.dbscWriteInstructions(w, r, body)
	slog.DebugContext(r.Context(), "dbsc refresh completed",
		"session_identifier_len", len(sctx.sessdata.DBSCSessionID))
	return true
}

func (m *Manager[T]) handleErr(w http.ResponseWriter, r *http.Request, err error) {
	if m.opts.ErrorHandler != nil {
		m.opts.ErrorHandler(w, r, err)
		return
	}
	slog.ErrorContext(r.Context(), "error in session manager", "err", err)
	http.Error(w, "Internal Error", http.StatusInternalServerError)
}

func (m *Manager[T]) dbscIssueInBandChallenge(w http.ResponseWriter, r *http.Request, sctx *Session[T]) {
	nonce, err := m.dbscStore.generateChallenge(r, sctx, false)
	if err != nil {
		m.handleErr(w, r, err)
		return
	}
	w.Header().Set("Secure-Session-Challenge", `"`+nonce+`";id="`+sctx.sessdata.DBSCSessionID+`"`)
	w.WriteHeader(http.StatusForbidden)
}

func (m *Manager[T]) dbscIssueRefreshChallenge(w http.ResponseWriter, r *http.Request, sctx *Session[T]) bool {
	nonce, err := m.dbscStore.generateChallenge(r, sctx, false)
	if err != nil {
		m.handleErr(w, r, err)
		return true
	}
	w.Header().Set("Secure-Session-Challenge", `"`+nonce+`";id="`+sctx.sessdata.DBSCSessionID+`"`)
	w.WriteHeader(http.StatusForbidden)
	return true
}

func deriveDBSCSessionID(jwks []byte) string {
	if len(jwks) == 0 {
		return ""
	}
	h := sha256.Sum256(jwks)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:])
}

func dbscSessionSkipped(r *http.Request) bool {
	v := r.Header.Get("Sec-Secure-Session-Skipped")
	if v == "" {
		v = r.Header.Get("Sec-Session-Skipped")
	}
	return v == "?1" || v == "1" || v == "true"
}
