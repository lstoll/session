package session

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"
)

/*type Sessionable interface {
	// // New is called on a nil receiver of this type. It should construct a new
	// // instance of the session type, for when a session is initialized. It can
	// // be used to set any defaults.
	NewSession() Sessionable
	// SessionName returns a unique name for this session type. It should be
	// constant, and may be called with a nil self.
	// SessionName() string
	SessionValid() bool
}*/

// Manager is used to automatically manage a typed session. It wraps handlers,
// and loads/saves the session type as needed. It provides methods to interact
// with the session.
type Manager[T any] struct {
	Store Store

	codec codec

	newEmpty func() T
}

func NewManager[T any, PtrT interface {
	*T
}](s Store) *Manager[PtrT] {
	// TODO - options with expiry
	m := &Manager[PtrT]{
		Store: s,
		newEmpty: func() PtrT {
			return PtrT(new(T))
		},
	}

	if _, ok := any(m.newEmpty()).(proto.Message); ok {
		m.codec = &protoCodec{}
	} else {
		m.codec = &jsonCodec{}
	}

	return m
}

func (a *Manager[T]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sctx := &sessCtx[T]{
			metadata: &sessionMetadata{
				CreatedAt: time.Now(),
			},
			data: a.newEmpty(),
		}

		data, err := a.Store.Get(r)
		if err != nil {
			a.handleErr(w, r, err)
			return
		}

		if data != nil {
			md, err := a.codec.Decode(data, sctx.data)
			if err != nil {
				a.handleErr(w, r, err)
				return
			}
			sctx.loaded = true
			sctx.metadata = md
		}

		r = r.WithContext(context.WithValue(r.Context(), mgrSessCtxKey[T]{inst: a}, sctx))

		hw := &hookRW{
			ResponseWriter: w,
			hook:           a.saveHook(r, sctx),
		}

		next.ServeHTTP(hw, r)

		// if the handler doesn't write anything, make sure we fire the hook
		// anyway.
		hw.hookOnce.Do(func() {
			hw.hook(hw.ResponseWriter)
		})
	})
}

func (a *Manager[T]) Get(ctx context.Context) (_ T, exist bool) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: a}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}

	return sessCtx.data, sessCtx.loaded
}

func (a *Manager[T]) Save(ctx context.Context, sess T) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: a}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.delete = false
	sessCtx.save = true
	sessCtx.data = sess
}

func (a *Manager[T]) Delete(ctx context.Context) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: a}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.delete = true
	sessCtx.save = false
	sessCtx.reset = false
}

func (a *Manager[T]) Reset(ctx context.Context, sess T) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: a}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.save = false
	sessCtx.delete = false
	sessCtx.reset = true

	// TODO - make reset KV only
	// maybe turn manager to private, have KVManager and CookieManager wrap it with
	// it mostly being pass-through. only expose the reset on the KVManager. then reset can maybe be smarter
	// about set-cookie with new ID, rather than delete/create.
}

func (a *Manager[T]) handleErr(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "error in session manager", "err", err)
	http.Error(w, "Internal Error", http.StatusInternalServerError)
}

func (a *Manager[T]) saveHook(r *http.Request, sctx *sessCtx[T]) func(w http.ResponseWriter) bool {
	return func(w http.ResponseWriter) bool {
		// if we have delete or reset, delete the session
		if sctx.delete || sctx.reset {
			if err := a.Store.Delete(w, r); err != nil {
				a.handleErr(w, r, err)
				return false
			}
		}

		// if we have reset or save, save the session
		if sctx.save || sctx.reset {
			sb, err := a.codec.Encode(sctx.data, sctx.metadata)
			if err != nil {
				a.handleErr(w, r, err)
				return false
			}

			if err := a.Store.Put(w, r, time.Now().Add(1*time.Minute), sb); err != nil {
				a.handleErr(w, r, err)
				return false
			}
		}

		return true
	}
}

type mgrSessCtxKey[T any] struct{ inst *Manager[T] }

type sessCtx[T any] struct {
	//loaded flags if this was an existing session
	loaded   bool
	metadata *sessionMetadata
	// data is the actual session data, untyped
	data   T
	delete bool
	save   bool
	reset  bool
}
