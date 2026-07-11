package session

import (
	"log/slog"
	"maps"
	"net/http"
	"sync"
)

type sessionContextKey struct {
	manager *Manager
}

// testSessionContextKey is used only by TestContext; it is not manager-scoped.
type testSessionContextKey struct{}

// dbscServeConfigKey is used by Manager.Wrap to pass registration path into
// InitiateDBSCRegistration.
type dbscServeConfigKey struct{}

type dbscServeConfig struct {
	RegistrationPath  string
	GenerateChallenge func(r *http.Request, sctx *Session, isRegister bool) (string, error)
}

// Session represents a tracked web session.
type Session struct {
	mgr      *Manager
	reqW     http.ResponseWriter
	reqR     *http.Request
	sessdata persistedSession
	sessdataMu sync.RWMutex
	// datab is the original loaded data bytes. Used for idle timeout, when a
	// save may happen without data modification
	datab  []byte
	delete bool
	save   bool
	reset  bool

	isNew    bool
	loaded   bool
	aborted  bool
	loadOnce sync.Once
}

// IsNew reports whether persisted session data has not been loaded from storage.
// It is true for brand-new sessions and after Reset or Delete. On lazy-loaded
// managers, it stays true until a session accessor (Get, Set, etc.) triggers
// the store read.
func (s *Session) IsNew() bool {
	if s.aborted {
		return s.isNew
	}

	s.sessdataMu.RLock()
	defer s.sessdataMu.RUnlock()
	return s.isNew
}

func (s *Session) ensureLoaded() {
	if s.mgr == nil || s.reqW == nil || s.reqR == nil {
		return
	}
	if s.mgr.ensureSessionLoaded(s.reqW, s.reqR, s) {
		return
	}
}

// Get returns the value for the given key from the session.
// If the key doesn't exist, it returns nil.
func (s *Session) Get(key string) any {
	s.ensureLoaded()
	if s.aborted {
		return nil
	}

	s.sessdataMu.RLock()
	defer s.sessdataMu.RUnlock()

	return s.sessdata.Data[key]
}

// GetAll returns a copy of the session data map.
func (s *Session) GetAll() map[string]any {
	s.ensureLoaded()
	if s.aborted {
		return nil
	}

	s.sessdataMu.RLock()
	defer s.sessdataMu.RUnlock()

	return maps.Clone(s.sessdata.Data)
}

// Set sets a single key-value pair in the session and marks it to be saved.
func (s *Session) Set(key string, value any) {
	s.ensureLoaded()
	if s.aborted {
		return
	}

	s.sessdataMu.Lock()
	defer s.sessdataMu.Unlock()

	s.delete = false
	s.save = true
	s.sessdata.Data[key] = value
}

// SetAll sets the entire session data map and marks it to be saved.
func (s *Session) SetAll(data map[string]any) {
	s.ensureLoaded()
	if s.aborted {
		return
	}

	s.sessdataMu.Lock()
	defer s.sessdataMu.Unlock()

	s.delete = false
	s.save = true

	s.sessdata.Data = data
}

// Delete marks the session for deletion at the end of the request.
func (s *Session) Delete() {
	s.ensureLoaded()

	s.sessdataMu.Lock()
	defer s.sessdataMu.Unlock()

	s.datab = nil
	s.sessdata = persistedSession{
		Data: make(map[string]any),
	}
	s.isNew = true
	s.delete = true
	s.save = false
	s.reset = false
}

// Reset rotates the session ID to avoid session fixation.
func (s *Session) Reset() {
	s.ensureLoaded()

	s.sessdataMu.Lock()
	defer s.sessdataMu.Unlock()

	s.datab = nil
	s.save = false
	s.delete = false
	s.reset = true
	s.isNew = true
}

// HasFlash indicates if there is a flash message.
func (s *Session) HasFlash() bool {
	s.ensureLoaded()
	if s.aborted {
		return false
	}
	return s.sessdata.Flash != flashLevelNone
}

// FlashIsError indicates that the flash message is an error.
func (s *Session) FlashIsError() bool {
	s.ensureLoaded()
	if s.aborted {
		return false
	}
	return s.sessdata.Flash == flashLevelError
}

// FlashMessage returns the current flash message and clears it.
func (s *Session) FlashMessage() string {
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
	s.save = true

	return flash
}

func (s *Session) SetFlashError(message string) {
	s.ensureLoaded()
	if s.aborted {
		return
	}
	s.sessdata.FlashMsg = message
	s.sessdata.Flash = flashLevelError
	s.save = true
}

func (s *Session) SetFlashMessage(message string) {
	s.ensureLoaded()
	if s.aborted {
		return
	}
	s.sessdata.FlashMsg = message
	s.sessdata.Flash = flashLevelInfo
	s.save = true
}

// IsDeviceBound returns true if the session is cryptographically bound to a device.
func (s *Session) IsDeviceBound() bool {
	s.ensureLoaded()
	if s.aborted {
		return false
	}

	s.sessdataMu.RLock()
	defer s.sessdataMu.RUnlock()
	return len(s.sessdata.DBSCPublicJWKS) > 0
}

// InitiateDBSCRegistration adds Secure-Session-Registration immediately.
// When DBSC is enabled, the manager normally attaches this header automatically
// on the first HTTP response that persists session data (after Set/SetAll), as
// long as the session is not yet device-bound and has at least one key in Data.
// Call this if you need a registration offer without that save (e.g. empty Data)
// or to replace the current pending challenge.
//
// Requires DBSCRefreshInterval and DBSCRegistrationPath on the session Manager.
func (s *Session) InitiateDBSCRegistration(w http.ResponseWriter, r *http.Request) {
	s.ensureLoaded()
	if s.aborted {
		return
	}

	cfg, ok := r.Context().Value(dbscServeConfigKey{}).(dbscServeConfig)
	if !ok || cfg.RegistrationPath == "" || cfg.GenerateChallenge == nil {
		http.Error(w, "DBSC registration not configured on session manager", http.StatusInternalServerError)
		return
	}

	challenge, err := cfg.GenerateChallenge(r, s, true)
	if err != nil {
		http.Error(w, "failed to generate registration challenge", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Secure-Session-Registration", `(ES256);path="`+cfg.RegistrationPath+`";challenge="`+challenge+`"`)
	slog.DebugContext(r.Context(), "dbsc InitiateDBSCRegistration",
		"path", cfg.RegistrationPath, "challenge_len", len(challenge))
}
