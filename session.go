package session

import (
	"log/slog"
	"net/http"
	"time"
)

type sessionContextKey[T any] struct {
	manager *Manager[T]
}

// dbscServeConfigKey is used by Manager.Wrap to pass registration path into
// InitiateDBSCRegistration.
type dbscServeConfigKey struct{}

type dbscServeConfig[T any] struct {
	RegistrationPath  string
	GenerateChallenge func(sctx *Session[T], isRegister bool) (string, error)
}

type sessionState uint8

const (
	sessionClean sessionState = iota
	sessionDirty
	sessionDeleted
)

// Session represents a tracked web session. A Session is scoped to one HTTP
// request and must not be accessed concurrently by multiple goroutines.
type Session[T any] struct {
	mgr      *Manager[T]
	reqW     http.ResponseWriter
	reqR     *http.Request
	sessdata persistedSession[T]
	// loadedData is the original encoded session. It lets idle-timeout touches
	// extend storage without re-encoding unchanged application data.
	loadedData []byte
	state      sessionState
	rotate     bool

	isNew   bool
	loaded  bool
	aborted bool
}

// IsNew reports whether persisted session data has not been loaded from storage.
// It is true for brand-new sessions and after Reset or Delete. On lazy-loaded
// managers, it stays true until a session accessor (Get, Set, etc.) triggers
// the store read.
func (s *Session[T]) IsNew() bool {
	return s.isNew
}

func (s *Session[T]) ensureLoaded() {
	if s.mgr == nil || s.reqW == nil || s.reqR == nil {
		return
	}
	s.mgr.ensureSessionLoaded(s.reqW, s.reqR, s)
}

// Get returns the application data stored in the session.
//
// The returned value is a copy of T. If T contains reference types such as
// maps, slices, or pointers, callers must call Set after making changes so the
// session is marked for saving.
func (s *Session[T]) Get() T {
	s.ensureLoaded()
	if s.aborted {
		var zero T
		return zero
	}

	return s.sessdata.Data
}

// Set replaces the application data and marks the session for saving.
func (s *Session[T]) Set(data T) {
	s.ensureLoaded()
	if s.aborted {
		return
	}

	if s.state == sessionDeleted {
		s.sessdata.CreatedAt = time.Now()
		s.rotate = true
	}
	s.state = sessionDirty
	s.sessdata.Data = data
}

// Delete marks the session for deletion at the end of the request.
func (s *Session[T]) Delete() {
	s.ensureLoaded()

	s.loadedData = nil
	s.sessdata = persistedSession[T]{}
	s.isNew = true
	s.state = sessionDeleted
	s.rotate = false
}

// Reset rotates the session ID to avoid session fixation.
func (s *Session[T]) Reset() {
	s.ensureLoaded()

	s.loadedData = nil
	if s.sessdata.CreatedAt.IsZero() {
		s.sessdata.CreatedAt = time.Now()
	}
	s.state = sessionDirty
	s.rotate = true
	s.isNew = true
}

// HasFlash indicates if there is a flash message.
func (s *Session[T]) HasFlash() bool {
	s.ensureLoaded()
	if s.aborted {
		return false
	}
	return s.sessdata.Flash != flashLevelNone
}

// FlashIsError indicates that the flash message is an error.
func (s *Session[T]) FlashIsError() bool {
	s.ensureLoaded()
	if s.aborted {
		return false
	}
	return s.sessdata.Flash == flashLevelError
}

// FlashMessage returns the current flash message and clears it.
func (s *Session[T]) FlashMessage() string {
	s.ensureLoaded()
	if s.aborted {
		return ""
	}

	flash := s.sessdata.FlashMsg
	if flash == "" {
		return ""
	}

	// Clear the flash, it's been read
	s.sessdata.FlashMsg = ""
	s.sessdata.Flash = flashLevelNone
	s.state = sessionDirty

	return flash
}

func (s *Session[T]) SetFlashError(message string) {
	s.ensureLoaded()
	if s.aborted {
		return
	}
	s.sessdata.FlashMsg = message
	s.sessdata.Flash = flashLevelError
	s.state = sessionDirty
}

func (s *Session[T]) SetFlashMessage(message string) {
	s.ensureLoaded()
	if s.aborted {
		return
	}
	s.sessdata.FlashMsg = message
	s.sessdata.Flash = flashLevelInfo
	s.state = sessionDirty
}

// IsDeviceBound returns true if the session is cryptographically bound to a device.
func (s *Session[T]) IsDeviceBound() bool {
	s.ensureLoaded()
	if s.aborted {
		return false
	}

	return len(s.sessdata.DBSCPublicJWKS) > 0
}

// InitiateDBSCRegistration adds Secure-Session-Registration immediately.
// When DBSC is enabled, the manager normally attaches this header automatically
// on the first HTTP response that persists session data (after Set), as long
// as the session is not yet device-bound. Call this if you
// need a registration offer without saving application data or want to replace
// the current pending challenge.
//
// Requires DBSCRefreshInterval and DBSCRegistrationPath on the session Manager.
func (s *Session[T]) InitiateDBSCRegistration(w http.ResponseWriter, r *http.Request) {
	s.ensureLoaded()
	if s.aborted {
		return
	}

	cfg, ok := r.Context().Value(dbscServeConfigKey{}).(dbscServeConfig[T])
	if !ok || cfg.RegistrationPath == "" || cfg.GenerateChallenge == nil {
		http.Error(w, "DBSC registration not configured on session manager", http.StatusInternalServerError)
		return
	}

	challenge, err := cfg.GenerateChallenge(s, true)
	if err != nil {
		http.Error(w, "failed to generate registration challenge", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Secure-Session-Registration", `(ES256);path="`+cfg.RegistrationPath+`";challenge="`+challenge+`"`)
	slog.DebugContext(r.Context(), "dbsc InitiateDBSCRegistration",
		"path", cfg.RegistrationPath, "challenge_len", len(challenge))
}
