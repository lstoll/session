package session

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type sessionContextKey[T any] struct {
	manager *Manager[T]
}

// FlashLevel identifies how an application should present a flash message.
// Applications may define additional levels.
type FlashLevel string

const (
	// FlashLevelInfo identifies an informational flash.
	FlashLevelInfo FlashLevel = "info"
	// FlashLevelError identifies an error flash.
	FlashLevelError FlashLevel = "error"
)

// Flash is a message that remains in the session until consumed by
// TakeFlashes.
type Flash struct {
	// Level controls how the application presents the message.
	Level FlashLevel `json:"level,omitempty"`
	// Message is the content presented to the user.
	Message string `json:"message"`
}

// dbscServeConfigKey is used by Manager.Wrap to pass registration path into
// InitiateDBSCRegistration.
type dbscServeConfigKey struct{}

type dbscServeConfig[T any] struct {
	RegistrationPath              string
	GenerateRegistrationChallenge func(sctx *Session[T], now time.Time) string
}

// Session is a request-scoped session. It is not safe for concurrent use.
type Session[T any] struct {
	mgr            *Manager[T]
	reqW           http.ResponseWriter
	reqR           *http.Request
	meta           sessionMeta
	working        *T
	payload        []byte
	zeroPayload    []byte
	deleted        bool
	rotate         bool
	dataScheduled  bool
	metaDirty      bool
	pendingSaveErr error

	isNew      bool
	loaded     bool
	aborted    bool
	loadFailed bool
}

func (m *Manager[T]) newRequestSession() *Session[T] {
	return &Session[T]{
		mgr:         m,
		isNew:       true,
		meta:        sessionMeta{CreatedAt: time.Now()},
		working:     new(T),
		payload:     append([]byte(nil), m.zeroPayload...),
		zeroPayload: append([]byte(nil), m.zeroPayload...),
	}
}

// IsNew reports whether the session has no loaded state. It is also true after
// Reset or Delete. With lazy loading, it remains true until the first access.
func (s *Session[T]) IsNew() bool {
	return s.isNew
}

func (s *Session[T]) ensureLoaded() {
	if s.mgr == nil || s.reqW == nil || s.reqR == nil {
		return
	}
	s.mgr.ensureSessionLoaded(s.reqW, s.reqR, s)
}

func (s *Session[T]) assertMutable(operation string) {
	if writer, ok := s.reqW.(interface{ responseCommitted() bool }); ok && writer.responseCommitted() {
		panic("session: " + operation + " called after response committed")
	}
}

// Get returns the request's application data. It never returns nil. Call Save
// after changing the data.
func (s *Session[T]) Get() *T {
	s.ensureLoaded()
	if s.working == nil {
		s.working = new(T)
	}
	return s.working
}

// Save snapshots the current application data for persistence at response
// commit. Later changes require another Save. Encoding errors are reported to
// the Manager's ErrorHandler at commit.
func (s *Session[T]) Save() {
	s.ensureLoaded()
	s.assertMutable("Save")
	if s.aborted || s.loadFailed {
		return
	}

	if err := s.snapshotData(); err != nil {
		s.pendingSaveErr = err
		return
	}
	s.reviveForWrite()
}

func (s *Session[T]) snapshotData() error {
	payload, err := s.mgr.codec.MarshalPayload(s.working)
	if err != nil {
		return fmt.Errorf("encoding application data: %w", err)
	}
	s.payload = payload
	s.dataScheduled = true
	s.pendingSaveErr = nil
	return nil
}

// reviveForWrite turns a deleted request session into a fresh active session.
// Its working pointer and zero-value payload were installed by markDeleted.
func (s *Session[T]) reviveForWrite() {
	if !s.deleted {
		return
	}
	s.meta.CreatedAt = time.Now()
	s.rotate = true
	s.deleted = false
}

// Delete schedules the session for deletion and replaces its application data
// with a new zero value. Pointers returned by an earlier Get are detached.
//
// A KV-backed Manager deletes stored state. A cookie-backed Manager can only
// expire the current client's cookie.
func (s *Session[T]) Delete() {
	s.ensureLoaded()
	s.assertMutable("Delete")
	if s.aborted || s.loadFailed {
		return
	}

	s.markDeleted()
}

func (s *Session[T]) markDeleted() {
	s.meta = sessionMeta{}
	s.working = new(T)
	s.payload = append([]byte(nil), s.zeroPayload...)
	s.isNew = true
	s.deleted = true
	s.rotate = false
	s.dataScheduled = false
	s.metaDirty = false
	s.pendingSaveErr = nil
}

// Reset rotates the session identifier and snapshots the current data. It also
// restarts the session lifetime.
//
// Use Reset when establishing an authenticated identity. A KV-backed Manager
// invalidates the old identifier. A cookie-backed Manager cannot revoke copies
// of an earlier cookie.
func (s *Session[T]) Reset() {
	s.ensureLoaded()
	s.assertMutable("Reset")
	if s.aborted || s.loadFailed {
		return
	}
	if err := s.snapshotData(); err != nil {
		s.pendingSaveErr = err
	}

	now := time.Now()
	s.meta.CreatedAt = now
	s.meta.UpdatedAt = now
	s.deleted = false
	s.rotate = true
	s.isNew = true
	s.metaDirty = true
}

// TakeFlashes returns and removes all queued flashes. It returns nil without
// scheduling a write when the queue is empty.
func (s *Session[T]) TakeFlashes() []Flash {
	s.ensureLoaded()
	if s.aborted || s.loadFailed {
		return nil
	}
	if len(s.meta.Flashes) == 0 {
		return nil
	}
	s.assertMutable("TakeFlashes")
	flashes := append([]Flash(nil), s.meta.Flashes...)
	s.meta.Flashes = nil
	s.metaDirty = true
	return flashes
}

// AddFlash queues a flash and schedules session metadata for persistence.
func (s *Session[T]) AddFlash(flash Flash) {
	s.ensureLoaded()
	s.assertMutable("AddFlash")
	if s.aborted || s.loadFailed {
		return
	}

	s.reviveForWrite()
	s.meta.Flashes = append(s.meta.Flashes, flash)
	s.metaDirty = true
}

// IsDeviceBound reports whether the session is bound to a device.
func (s *Session[T]) IsDeviceBound() bool {
	s.ensureLoaded()
	if s.aborted || s.loadFailed {
		return false
	}

	return len(s.meta.DBSCPublicJWK) > 0
}

// InitiateDBSCRegistration adds a Secure-Session-Registration header without
// saving application data. It does nothing for a bound session or a request
// that is not eligible for registration.
//
// The Manager must configure DBSCRefreshInterval and DBSCRegistrationPath.
func (s *Session[T]) InitiateDBSCRegistration(w http.ResponseWriter, r *http.Request) {
	s.ensureLoaded()
	s.assertMutable("InitiateDBSCRegistration")
	if s.aborted {
		return
	}
	if len(s.meta.DBSCPublicJWK) > 0 {
		slog.DebugContext(r.Context(), "dbsc InitiateDBSCRegistration skipped", "reason", "already_device_bound")
		return
	}
	if !dbscShouldOfferRegistration(r) {
		slog.DebugContext(r.Context(), "dbsc InitiateDBSCRegistration skipped", "reason", "not_first_party",
			dbscFetchMetadata(r))
		return
	}

	cfg, ok := r.Context().Value(dbscServeConfigKey{}).(dbscServeConfig[T])
	if !ok || cfg.RegistrationPath == "" || cfg.GenerateRegistrationChallenge == nil {
		http.Error(w, "DBSC registration not configured on session manager", http.StatusInternalServerError)
		return
	}

	challenge := cfg.GenerateRegistrationChallenge(s, time.Now())

	w.Header().Add("Secure-Session-Registration", dbscRegistrationHeader(cfg.RegistrationPath, challenge))
	slog.DebugContext(r.Context(), "dbsc InitiateDBSCRegistration",
		"path", cfg.RegistrationPath, "challenge_len", len(challenge))
}
