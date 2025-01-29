package session

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"
)

type store interface {
	// get loads the encoded data for a session from the request. If there is no
	// session data, it should return nil
	get(r *http.Request) ([]byte, error)
	// put saves a session. If a session exists it should be updated, otherwise
	// a new session should be created.
	put(w http.ResponseWriter, r *http.Request, expiresAt time.Time, data []byte) error
	// delete deletes the session.
	delete(w http.ResponseWriter, r *http.Request) error
}

// manager is used to automatically manage a typed session. It wraps handlers,
// and loads/saves the session type as needed. It provides methods to interact
// with the session.
type manager[T any] struct {
	store store

	codec codec

	newEmpty func() T

	opts managerOpts
}

type managerOpts struct {
	// expiry sets the duration from now we should use for the store put
	expiry time.Duration
}

func newManager[T any, PtrT interface {
	*T
}](s store, opts *managerOpts) *manager[PtrT] {
	// TODO - options with expiry
	m := &manager[PtrT]{
		store: s,
		newEmpty: func() PtrT {
			return PtrT(new(T))
		},
	}

	if opts != nil {
		m.opts = *opts
	}

	if _, ok := any(m.newEmpty()).(proto.Message); ok {
		m.codec = &protoCodec{}
	} else {
		m.codec = &jsonCodec{}
	}

	return m
}

func (m *manager[T]) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sctx := &sessCtx[T]{
			metadata: &sessionMetadata{
				CreatedAt: time.Now(),
			},
			data: m.newEmpty(),
		}

		data, err := m.store.get(r)
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
			sctx.loaded = true
			sctx.metadata = md
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

func (m *manager[T]) get(ctx context.Context) (_ T, exist bool) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}

	return sessCtx.data, sessCtx.loaded
}

func (m *manager[T]) save(ctx context.Context, sess T) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.delete = false
	sessCtx.save = true
	sessCtx.data = sess
}

func (m *manager[T]) delete(ctx context.Context) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.delete = true
	sessCtx.save = false
	sessCtx.reset = false
}

func (m *manager[T]) reset(ctx context.Context, sess T) {
	sessCtx, ok := ctx.Value(mgrSessCtxKey[T]{inst: m}).(*sessCtx[T])
	if !ok {
		panic("context contained no or invalid session")
	}
	sessCtx.data = sess
	sessCtx.save = false
	sessCtx.delete = false
	sessCtx.reset = true
}

func (m *manager[T]) handleErr(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "error in session manager", "err", err)
	http.Error(w, "Internal Error", http.StatusInternalServerError)
}

func (m *manager[T]) saveHook(r *http.Request, sctx *sessCtx[T]) func(w http.ResponseWriter) bool {
	return func(w http.ResponseWriter) bool {
		// if we have delete or reset, delete the session
		if sctx.delete || sctx.reset {
			if err := m.store.delete(w, r); err != nil {
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

			if err := m.store.put(w, r, time.Now().Add(m.opts.expiry), sb); err != nil {
				m.handleErr(w, r, err)
				return false
			}
		}

		return true
	}
}

type mgrSessCtxKey[T any] struct{ inst *manager[T] }

type sessCtx[T any] struct {
	//loaded flags if this was an existing session
	loaded   bool
	metadata *sessionMetadata
	// data is the actual session data
	data   T
	delete bool
	save   bool
	reset  bool
}
