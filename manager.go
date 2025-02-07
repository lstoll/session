package session

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"
)

// sessionMetadata tracks additional information for the session manager to use,
// alongside the session data itself.
type sessionMetadata struct {
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Store interface {
	// GetSession loads the encoded data for a session from the request. If there is no
	// session data, it should return nil.
	GetSession(r *http.Request) ([]byte, error)
	// PutSession saves a session. If a session exists it should be updated,
	// otherwise a new session should be created. expiresAt indicates the time
	// the data can be considered to be no longer used, and can be garbage
	// collected.
	PutSession(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error
	// DeleteSession deletes the session.
	DeleteSession(w http.ResponseWriter, r *http.Request) error
}

// Manager is used to automatically manage a typed session. It wraps handlers,
// and loads/saves the session type as needed. It provides methods to interact
// with the session.
type Manager[T any] struct {
	store Store

	codec codec

	newEmpty func() T

	opts ManagerOpts[T]
}

var DefaultIdleTimeout = 24 * time.Hour

type ManagerOpts[T any] struct {
	MaxLifetime time.Duration
	IdleTimeout time.Duration
	// Onload is called when a session is retrieved from the Store. It can make
	// any changes as needed, returning the session that should be used.
	Onload func(T) T
}

func NewManager[T any, PtrT interface {
	*T
}](s Store, opts *ManagerOpts[PtrT]) (*Manager[PtrT], error) {
	// TODO - options with expiry
	m := &Manager[PtrT]{
		store: s,
		newEmpty: func() PtrT {
			return PtrT(new(T))
		},
		opts: ManagerOpts[PtrT]{
			IdleTimeout: DefaultIdleTimeout,
		},
	}

	if opts != nil {
		m.opts = *opts
	}

	if m.opts.IdleTimeout == 0 && m.opts.MaxLifetime == 0 {
		return nil, errors.New("at least one of idle timeout or max lifetime must be specified")
	}

	if _, ok := any(m.newEmpty()).(proto.Message); ok {
		m.codec = &protoCodec{}
	} else {
		m.codec = &jsonCodec{}
	}

	return m, nil
}

func (m *Manager[T]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T]); ok {
			// already wrapped for this instance, noop
			next.ServeHTTP(w, r)
			return
		}

		sctx := &sessCtx[T]{
			metadata: &sessionMetadata{
				CreatedAt: time.Now(),
			},
			data: m.newEmpty(),
		}

		data, err := m.store.GetSession(r)
		if err != nil {
			m.handleErr(w, r, err)
			return
		}

		if data != nil {
			md, err := m.codec.Decode(data, sctx.data)
			if err != nil {
				m.handleErr(w, r, err)
				return
			}
			sctx.metadata = md
			// track the original data if we have an idle timeout, so we can
			// short path re-save it.
			if m.opts.IdleTimeout != 0 {
				sctx.datab = data
			}
			if m.opts.Onload != nil {
				sctx.data = m.opts.Onload(sctx.data)
			}
		}

		r = r.WithContext(context.WithValue(r.Context(), mgrSessCtxKey[T]{inst: m}, sctx))

		hw := &hookRW{
			ResponseWriter: w,
			hook:           m.saveHook(r, sctx),
		}

		next.ServeHTTP(hw, r)

		// if the handler doesn't write anything, make sure we fire the hook
		// anyway.
		hw.hookOnce.Do(func() {
			hw.hook(hw.ResponseWriter)
		})
	})
}

// Get returns a pointer to the current session. exist indicates if an existing
// session was loaded, otherwise a new session was started
func (m *Manager[T]) Get(ctx context.Context) (_ T) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}

	return sessCtx.data
}

// Save sets the session data, and marks it to be saved at the end of the
// request.
func (m *Manager[T]) Save(ctx context.Context, sess T) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.delete = false
	sessCtx.save = true
	sessCtx.data = sess
}

// Delete marks the session for deletion at the end of the request, and discards
// the current session's data.
func (m *Manager[T]) Delete(ctx context.Context) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.datab = nil
	sessCtx.data = m.newEmpty()
	sessCtx.delete = true
	sessCtx.save = false
	sessCtx.reset = false
}

// Reset rotates the session ID. Used to avoid session fixation, should be
// called on privilege elevation. This should be called at the end of a request.
// If this is not supported by the store, this will no-op.
func (m *Manager[T]) Reset(ctx context.Context, sess T) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.data = sess
	sessCtx.datab = nil
	sessCtx.save = false
	sessCtx.delete = false
	sessCtx.reset = true
}

func (m *Manager[T]) handleErr(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "error in session manager", "err", err)
	http.Error(w, "Internal Error", http.StatusInternalServerError)
}

func (m *Manager[T]) saveHook(r *http.Request, sctx *sessCtx[T]) func(w http.ResponseWriter) bool {
	return func(w http.ResponseWriter) bool {
		sctx.metadata.UpdatedAt = time.Now()

		// if we have delete or reset, delete the session
		if sctx.delete || sctx.reset {
			if err := m.store.DeleteSession(w, r); err != nil {
				m.handleErr(w, r, err)
				return false
			}
		}

		// if we have reset or save, save the session
		if sctx.save || sctx.reset {
			sb, err := m.codec.Encode(sctx.data, sctx.metadata)
			if err != nil {
				m.handleErr(w, r, err)
				return false
			}

			if err := m.store.PutSession(w, r, m.calculateExpiry(sctx.metadata), sb); err != nil {
				m.handleErr(w, r, err)
				return false
			}
		} else if m.opts.IdleTimeout != 0 && len(sctx.datab) != 0 {
			// always need to bump the last access time. If we weren't marked to
			// save, do this with the original data.
			if err := m.store.PutSession(w, r, m.calculateExpiry(sctx.metadata), sctx.datab); err != nil {
				m.handleErr(w, r, err)
				return false
			}
		}

		return true
	}
}

func (m *Manager[T]) calculateExpiry(md *sessionMetadata) time.Time {
	var invalidTimes []time.Time

	if m.opts.MaxLifetime != 0 {
		maxInvalidAt := md.CreatedAt.Add(m.opts.MaxLifetime)
		invalidTimes = append(invalidTimes, maxInvalidAt)
	}

	if m.opts.IdleTimeout != 0 {
		var idleInvalidAt time.Time
		if !md.UpdatedAt.IsZero() {
			idleInvalidAt = md.UpdatedAt.Add(m.opts.IdleTimeout)
		} else {
			idleInvalidAt = md.CreatedAt.Add(m.opts.IdleTimeout)
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

type mgrSessCtxKey[T any] struct{ inst *Manager[T] }

type sessCtx[T any] struct {
	metadata *sessionMetadata
	// data is the actual session data
	data T
	// datab is the original loaded data bytes. Used for idle timeout, when a
	// save may happen without data modification
	datab  []byte
	delete bool
	save   bool
	reset  bool
}
