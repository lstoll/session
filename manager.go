package session

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"lds.li/session/internal/dbscproof"
	"lds.li/session/internal/testsession"
)

// FromContext returns the Session this Manager stored in ctx.
// It panics if this Manager did not install a session in ctx.
func (m *Manager[T]) FromContext(ctx context.Context) *Session[T] {
	sess, ok := ctx.Value(sessionContextKey[T]{manager: m}).(*Session[T])
	if ok {
		return sess
	}

	testState, ok := testsession.FromContext[T](ctx, m)
	if !ok {
		panic("no session in context for this Manager")
	}
	if existing := testState.Session(); existing != nil {
		return existing.(*Session[T])
	}

	initial := testState.Initial()
	sess = &Session[T]{
		mgr:      m,
		isNew:    initial.IsNew,
		loaded:   true,
		sessdata: persistedSession[T]{Data: initial.Data, CreatedAt: time.Now()},
	}
	for _, flash := range initial.Flashes {
		sess.sessdata.Flashes = append(sess.sessdata.Flashes, Flash{
			Level:   FlashLevel(flash.Level),
			Message: flash.Message,
		})
	}
	testState.Bind(sess, func() testsession.Snapshot[T] {
		flashes := make([]testsession.Flash, len(sess.sessdata.Flashes))
		for i, flash := range sess.sessdata.Flashes {
			flashes[i] = testsession.Flash{
				Level:   string(flash.Level),
				Message: flash.Message,
			}
		}
		return testsession.Snapshot[T]{
			Data:    sess.sessdata.Data,
			Saved:   sess.state == sessionDirty,
			Deleted: sess.state == sessionDeleted,
			Reset:   sess.rotate,
			IsNew:   sess.isNew,
			Flashes: flashes,
		}
	})
	return sess
}

type sessionStore[T any] interface {
	load(r *http.Request) (persistedSession[T], []byte, error)
	save(w http.ResponseWriter, r *http.Request, expiresAt time.Time, sess persistedSession[T]) error
	delete(r *http.Request) error
	touch(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error
}

// Manager handles both session data and storage.
type Manager[T any] struct {
	store          sessionStore[T]
	cookieSettings SessionCookieOpts
	codec          codec[T]
	opts           managerOpts[T]
	lazyLoad       bool
}

// DefaultIdleTimeout is used when neither manager lifetime option is set.
const DefaultIdleTimeout = 24 * time.Hour

// SessionCookieOpts configures the cookie emitted by a session manager.
type SessionCookieOpts struct {
	// Name must be a valid HTTP cookie name. Names beginning with __Host- must
	// use Path "/" and a secure cookie; names beginning with __Secure- must use
	// a secure cookie.
	Name string
	// Path must be an absolute cookie path beginning with "/".
	Path string
	// Insecure permits sending the cookie over HTTP. It should only be used for
	// local development without TLS.
	Insecure bool
	// Persist adds Max-Age so the browser may retain the cookie across restarts.
	Persist bool
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
		hc.MaxAge = managerCookieMaxAge(time.Until(exp))
	}
	return hc
}

func managerCookieMaxAge(remaining time.Duration) int {
	if remaining <= 0 {
		return -1
	}
	seconds := remaining / time.Second
	if remaining%time.Second != 0 {
		seconds++
	}
	return int(seconds)
}

type managerOpts[T any] struct {
	MaxLifetime  time.Duration
	IdleTimeout  time.Duration
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
	Onload       func(T) T
	CookieOpts   *SessionCookieOpts
	Codec        Codec

	DBSCRefreshInterval  time.Duration
	DBSCRegistrationPath string
	DBSCRefreshPath      string
	DBSCOrigin           string
}

// CookieManagerOpts configures options specifically for the cookie-based session manager
type CookieManagerOpts[T any] struct {
	// MaxLifetime is the maximum duration a session remains valid after its
	// creation. Zero disables the limit; negative values are rejected.
	MaxLifetime time.Duration
	// IdleTimeout is extended whenever a loaded session is used. Zero disables
	// the limit; negative values are rejected.
	IdleTimeout time.Duration
	// ErrorHandler handles failures that prevent the manager from safely loading
	// or persisting session state. When nil, the manager logs the error and
	// responds 500.
	ErrorHandler func(http.ResponseWriter, *http.Request, error)
	// Onload is called when a session is retrieved from storage.
	Onload func(T) T
	// Cookie settings.
	CookieOpts *SessionCookieOpts
	// Codec selects the persisted session encoding. Nil uses JSONCodec.
	Codec Codec
}

// KVManagerOpts configures options specifically for the KV-based session manager
type KVManagerOpts[T any] struct {
	// MaxLifetime is the maximum duration a session remains valid after its
	// creation. Zero disables the limit; negative values are rejected.
	MaxLifetime time.Duration
	// IdleTimeout is extended whenever a loaded session is used. Zero disables
	// the limit; negative values are rejected.
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
	// Codec selects the persisted session encoding. Nil uses JSONCodec.
	Codec Codec
	// SessionIDAuthenticator authenticates the opaque session ID cookie. When
	// set, invalid cookies are rejected before they can cause a KV lookup.
	SessionIDAuthenticator Authenticator

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

// NewCookieManager creates a new Manager that stores session data in cookies.
// It accepts any concurrency-safe cipher.AEAD. The manager generates and
// prefixes nonces for conventional AEADs; an AEAD with a zero nonce size, such
// as cipher.NewGCMWithRandomNonce, manages its own nonce framing.
//
// Cookie-backed sessions cannot be revoked server-side. Delete removes the
// current browser's cookie and Reset reissues it, but previously copied cookie
// values remain valid until their configured expiration. Use NewKVManager when
// server-side revocation or session ID rotation is required.
func NewCookieManager[T any](aead cipher.AEAD, opts *CookieManagerOpts[T]) (*Manager[T], error) {
	normalized := normalizeCookieManagerOpts(opts)
	if aead == nil {
		return nil, errors.New("AEAD is required")
	}
	selectedCodec, err := resolveCodec[T](normalized.Codec)
	if err != nil {
		return nil, err
	}
	m := &Manager[T]{
		opts:  normalized,
		codec: selectedCodec,
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
	if err := validateManagerOpts(m.opts, m.cookieSettings); err != nil {
		return nil, err
	}

	m.store = &cookieStore[T]{
		aead:           aead,
		codec:          m.codec,
		cookieSettings: m.cookieSettings,
	}

	return m, nil
}

// NewKVManager creates a new Manager that stores session data in a KV store
func NewKVManager[T any](kv KV, opts *KVManagerOpts[T]) (*Manager[T], error) {
	if kv == nil {
		return nil, errors.New("KV store is required")
	}
	normalized, sessionIDAuthenticator, eagerLoad := normalizeKVManagerOpts(opts)
	selectedCodec, err := resolveCodec[T](normalized.Codec)
	if err != nil {
		return nil, err
	}
	m := &Manager[T]{
		opts:  normalized,
		codec: selectedCodec,
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
	if err := validateManagerOpts(m.opts, m.cookieSettings); err != nil {
		return nil, err
	}

	m.store = &kvStore[T]{
		m:              m,
		kv:             kv,
		codec:          m.codec,
		cookieSettings: m.cookieSettings,
		authenticator:  sessionIDAuthenticator,
	}

	m.lazyLoad = !eagerLoad

	return m, nil
}

func normalizeCookieManagerOpts[T any](opts *CookieManagerOpts[T]) managerOpts[T] {
	if opts == nil {
		return managerOpts[T]{IdleTimeout: DefaultIdleTimeout}
	}
	normalized := managerOpts[T]{
		MaxLifetime:  opts.MaxLifetime,
		IdleTimeout:  opts.IdleTimeout,
		ErrorHandler: opts.ErrorHandler,
		Onload:       opts.Onload,
		CookieOpts:   opts.CookieOpts,
		Codec:        opts.Codec,
	}
	if normalized.IdleTimeout == 0 && normalized.MaxLifetime == 0 {
		normalized.IdleTimeout = DefaultIdleTimeout
	}
	return normalized
}

func normalizeKVManagerOpts[T any](opts *KVManagerOpts[T]) (managerOpts[T], Authenticator, bool) {
	if opts == nil {
		return managerOpts[T]{IdleTimeout: DefaultIdleTimeout}, nil, false
	}
	normalized := managerOpts[T]{
		MaxLifetime:          opts.MaxLifetime,
		IdleTimeout:          opts.IdleTimeout,
		ErrorHandler:         opts.ErrorHandler,
		Onload:               opts.Onload,
		CookieOpts:           opts.CookieOpts,
		Codec:                opts.Codec,
		DBSCRefreshInterval:  opts.DBSCRefreshInterval,
		DBSCRegistrationPath: opts.DBSCRegistrationPath,
		DBSCRefreshPath:      opts.DBSCRefreshPath,
		DBSCOrigin:           opts.DBSCOrigin,
	}
	if normalized.IdleTimeout == 0 && normalized.MaxLifetime == 0 {
		normalized.IdleTimeout = DefaultIdleTimeout
	}
	return normalized, opts.SessionIDAuthenticator, opts.EagerLoad
}

func validateManagerOpts[T any](opts managerOpts[T], cookieOpts SessionCookieOpts) error {
	if opts.MaxLifetime < 0 {
		return errors.New("MaxLifetime must not be negative")
	}
	if opts.IdleTimeout < 0 {
		return errors.New("IdleTimeout must not be negative")
	}
	if opts.IdleTimeout == 0 && opts.MaxLifetime == 0 {
		return errors.New("at least one of IdleTimeout or MaxLifetime must be specified")
	}
	if !strings.HasPrefix(cookieOpts.Path, "/") {
		return errors.New("session cookie Path must be an absolute path beginning with /")
	}
	cookie := cookieOpts.newCookie(time.Now().Add(time.Hour))
	cookie.Value = "validation"
	if err := cookie.Valid(); err != nil {
		return fmt.Errorf("invalid session cookie options: %w", err)
	}
	if err := managerValidateCookieSize(cookie); err != nil {
		return fmt.Errorf("invalid session cookie options: %w", err)
	}
	if strings.HasPrefix(cookieOpts.Name, "__Host-") {
		if cookieOpts.Insecure {
			return errors.New("session cookie names beginning with __Host- require Secure")
		}
		if cookieOpts.Path != "/" {
			return errors.New("session cookie names beginning with __Host- require Path /")
		}
	}
	if strings.HasPrefix(cookieOpts.Name, "__Secure-") && cookieOpts.Insecure {
		return errors.New("session cookie names beginning with __Secure- require Secure")
	}
	return nil
}

func validateDBSCOpts[T any](opts managerOpts[T]) error {
	if opts.DBSCRefreshInterval < 0 {
		return errors.New("DBSCRefreshInterval must not be negative")
	}
	if opts.DBSCRefreshInterval == 0 {
		return nil
	}
	origin, err := url.Parse(opts.DBSCOrigin)
	if err != nil || origin.Host == "" || origin.Scheme != "https" ||
		origin.User != nil || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("DBSCOrigin must be an HTTPS origin without a path, query, fragment, or userinfo")
	}
	for name, path := range map[string]string{
		"DBSCRegistrationPath": opts.DBSCRegistrationPath,
		"DBSCRefreshPath":      opts.DBSCRefreshPath,
	} {
		if path != "" && (!strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") || !isASCIIPrintable(path)) {
			return fmt.Errorf("%s must be an absolute URL path without a query or fragment", name)
		}
	}
	return nil
}

func isASCIIPrintable(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Constants for cookie format in the Manager
const (
	managerCookieMagic      = "EU1"
	managerMaxSetCookieSize = 4096
)

var managerCookieValueEncoding = base64.RawURLEncoding

// Wrap creates middleware that handles session management for each request.
// Session mutations must occur before the response is written or flushed;
// mutating a session after the response is committed panics.
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

		if dbscEnabled && !m.lazyLoad && len(sctx.sessdata.DBSCPublicJWK) > 0 {
			if m.runDBSCInBand(hw, r, sctx) {
				return
			}
		}

		ctx := context.WithValue(r.Context(), sessionContextKey[T]{manager: m}, sctx)
		if dbscEnabled {
			ctx = context.WithValue(ctx, dbscServeConfigKey{}, dbscServeConfig[T]{
				RegistrationPath:              m.dbscRegistrationPath(),
				GenerateRegistrationChallenge: issueDBSCRegistrationChallenge[T],
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
	if len(sctx.sessdata.DBSCPublicJWK) > 0 && sctx.sessdata.DBSCCurrentCookieID == "" {
		sctx.sessdata.DBSCCurrentCookieID = rand.Text()
	}

	// Calculate expiry
	expiresAt := m.calculateExpiry(sctx.sessdata)

	// Set DBSC bound cookie if device-bound
	if err := m.setDBSCBoundCookie(w, sctx); err != nil {
		return fmt.Errorf("setting DBSC bound cookie: %w", err)
	}

	return m.store.save(w, r, expiresAt, sctx.sessdata)
}

// deleteSession deletes the session from the appropriate storage
func (m *Manager[T]) deleteSession(w http.ResponseWriter, r *http.Request, sctx *Session[T]) error {
	// Delete cookie regardless of storage mode
	dc := m.cookieSettings.newCookie(time.Time{})
	dc.MaxAge = -1
	managerRemoveCookieByName(w, dc.Name)
	if err := managerSetCookie(w, dc); err != nil {
		return err
	}

	// Also delete the DBSC bound cookie
	if err := m.deleteDBSCBoundCookie(w); err != nil {
		return err
	}

	return m.store.delete(r)
}

// touchSession advances the idle deadline without persisting changes made by
// Onload. loadedData is the original encoded session, so decode it and update
// only the timestamp used to calculate idle expiry.
func (m *Manager[T]) touchSession(w http.ResponseWriter, r *http.Request, sctx *Session[T]) error {
	persisted, err := m.codec.Decode(sctx.loadedData)
	if err != nil {
		return fmt.Errorf("decoding session for idle timeout refresh: %w", err)
	}

	updatedAt := time.Now()
	persisted.UpdatedAt = updatedAt
	sctx.sessdata.UpdatedAt = updatedAt

	data, err := m.codec.Encode(persisted)
	if err != nil {
		return fmt.Errorf("encoding session for idle timeout refresh: %w", err)
	}

	expiresAt := m.calculateExpiry(persisted)
	return m.store.touch(w, r, expiresAt, data)
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

//nolint:unused // Called through generic store implementations; golangci-lint does not resolve the instantiation.
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

func managerValidateCookieSize(cookie *http.Cookie) error {
	size := len(cookie.String())
	if size > managerMaxSetCookieSize {
		return fmt.Errorf("serialized cookie size %d is greater than max %d", size, managerMaxSetCookieSize)
	}
	return nil
}

func managerSetCookie(w http.ResponseWriter, cookie *http.Cookie) error {
	if err := managerValidateCookieSize(cookie); err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	return nil
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
	if len(sctx.sessdata.DBSCPublicJWK) != 0 {
		slog.DebugContext(r.Context(), "dbsc registration offer skipped", "reason", "already_device_bound")
		return
	}
	now := time.Now()
	if hasPendingDBSCRegistrationChallenge(sctx, now) {
		slog.DebugContext(r.Context(), "dbsc registration offer skipped", "reason", "challenge_already_pending")
		return
	}

	challenge := issueDBSCRegistrationChallenge(sctx, now)

	w.Header().Add("Secure-Session-Registration", dbscRegistrationHeader(m.dbscRegistrationPath(), challenge))
	slog.DebugContext(r.Context(), "dbsc registration offer attached",
		"registration_path", m.dbscRegistrationPath(),
		"challenge_len", len(challenge))
}

func (m *Manager[T]) dbscBoundCookieName() string {
	return m.cookieSettings.Name + "-bound"
}

func (m *Manager[T]) setDBSCBoundCookie(w http.ResponseWriter, sctx *Session[T]) error {
	if len(sctx.sessdata.DBSCPublicJWK) == 0 {
		return nil
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
		hc.MaxAge = managerCookieMaxAge(time.Until(sctx.sessdata.DBSCExpiration))
	case m.opts.DBSCRefreshInterval > 0:
		hc.MaxAge = managerCookieMaxAge(m.opts.DBSCRefreshInterval)
	}
	managerRemoveCookieByName(w, hc.Name)
	return managerSetCookie(w, hc)
}

func (m *Manager[T]) deleteDBSCBoundCookie(w http.ResponseWriter) error {
	dc := &http.Cookie{
		Name:     m.dbscBoundCookieName(),
		Path:     m.cookieSettings.Path,
		Secure:   !m.cookieSettings.Insecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	managerRemoveCookieByName(w, dc.Name)
	return managerSetCookie(w, dc)
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

func (m *Manager[T]) dbscWriteExistingInstructions(w http.ResponseWriter, r *http.Request, sctx *Session[T]) bool {
	body, err := m.dbscRegistrationInstructions(sctx.sessdata.DBSCSessionID)
	if err != nil {
		m.handleErr(w, r, err)
		return true
	}
	m.dbscWriteInstructions(w, r, body)
	slog.DebugContext(r.Context(), "dbsc registration replayed existing instructions",
		"session_identifier_len", len(sctx.sessdata.DBSCSessionID))
	return true
}

// dbscWriteInstructions sets headers, writes the JSON body, and logs warnings.
func (m *Manager[T]) dbscWriteInstructions(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Set("Cache-Control", "no-store")
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
	if !dbscSameOriginRequest(r) {
		http.Error(w, "Cross-site registration rejected", http.StatusForbidden)
		return true
	}
	slog.DebugContext(r.Context(), "dbsc registration handler considering request",
		"method", r.Method, "path", r.URL.Path,
		"has_jwk", len(sctx.sessdata.DBSCPublicJWK) > 0)
	if len(sctx.sessdata.DBSCPublicJWK) != 0 {
		return m.dbscWriteExistingInstructions(w, r, sctx)
	}

	now := time.Now()
	if !hasPendingDBSCRegistrationChallenge(sctx, now) {
		slog.DebugContext(r.Context(), "dbsc registration POST rejected", "reason", "no_pending_challenge")
		http.Error(w, "invalid registration proof", http.StatusUnauthorized)
		return true
	}

	tok := dbscSessionResponseHeader(r)
	if tok == "" {
		slog.DebugContext(r.Context(), "dbsc registration POST rejected", "reason", "missing_secure_session_response")
		http.Error(w, "missing Secure-Session-Response", http.StatusBadRequest)
		return true
	}
	slog.DebugContext(r.Context(), "dbsc registration verifying proof", "header_len", len(tok))

	registration, err := dbscproof.VerifyRegistration(tok)
	if err != nil {
		slog.WarnContext(r.Context(), "DBSC registration proof rejected", "err", err)
		http.Error(w, "invalid registration proof", http.StatusUnauthorized)
		return true
	}

	if err := verifyDBSCRegistrationChallenge(sctx, registration.Challenge, now); err != nil {
		slog.WarnContext(r.Context(), "DBSC registration challenge verification failed", "err", err)
		http.Error(w, "invalid registration proof", http.StatusUnauthorized)
		return true
	}

	sessionID := rand.Text()

	sctx.sessdata.DBSCRegistrationChallenge = dbscChallenge{}
	sctx.sessdata.DBSCAlgorithm = registration.Key.Algorithm
	sctx.sessdata.DBSCPublicJWK = registration.Key.JWK
	sctx.sessdata.DBSCSessionID = sessionID
	sctx.sessdata.DBSCExpiration = now.Add(m.opts.DBSCRefreshInterval)
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
	if !dbscSameOriginRequest(r) {
		http.Error(w, "Cross-site refresh rejected", http.StatusForbidden)
		return true
	}
	if len(sctx.sessdata.DBSCPublicJWK) == 0 {
		http.Error(w, "session not device-bound", http.StatusUnauthorized)
		return true
	}
	if m.rejectDBSCSkipped(w, r, sctx.sessdata.DBSCSessionID) {
		return true
	}

	sessionID, ok := dbscSessionIDHeader(r)
	if !ok || sessionID == "" || sessionID != sctx.sessdata.DBSCSessionID {
		http.Error(w, "invalid Sec-Secure-Session-Id", http.StatusUnauthorized)
		return true
	}

	tok := dbscSessionResponseHeader(r)
	if tok == "" {
		return m.dbscIssueRefreshChallenge(w, r, sctx)
	}

	now := time.Now()
	jti, err := dbscproof.VerifyRefresh(tok, registeredDBSCKey(sctx))
	if err != nil {
		slog.WarnContext(r.Context(), "DBSC refresh proof rejected", "err", err)
		http.Error(w, "invalid refresh proof", http.StatusUnauthorized)
		return true
	}

	if err := verifyDBSCRefreshChallenge(sctx, jti, now); err != nil {
		slog.WarnContext(r.Context(), "DBSC refresh challenge verification failed", "err", err)
		return m.dbscIssueRefreshChallenge(w, r, sctx)
	}

	consumeDBSCRefreshChallenge(sctx, jti, now)

	sctx.sessdata.DBSCExpiration = now.Add(m.opts.DBSCRefreshInterval)

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
	nonce, err := issueDBSCRefreshChallenge(sctx, time.Now())
	if err != nil {
		m.handleErr(w, r, err)
		return
	}
	w.Header().Set("Secure-Session-Challenge", sfString(nonce)+`;id=`+sfString(sctx.sessdata.DBSCSessionID))
	w.WriteHeader(http.StatusForbidden)
}

func (m *Manager[T]) dbscIssueRefreshChallenge(w http.ResponseWriter, r *http.Request, sctx *Session[T]) bool {
	nonce, err := issueDBSCRefreshChallenge(sctx, time.Now())
	if err != nil {
		m.handleErr(w, r, err)
		return true
	}
	w.Header().Set("Secure-Session-Challenge", sfString(nonce)+`;id=`+sfString(sctx.sessdata.DBSCSessionID))
	w.WriteHeader(http.StatusForbidden)
	return true
}
