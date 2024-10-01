package session

import (
	"context"
	"net/http"
)

type Sessionable interface {
	New() Sessionable

	Expired() bool
}

type Store interface {
	LoadSession(name string, r *http.Request, into any) error
	SaveSession(name string, w http.ResponseWriter, r *http.Request, data []byte) error
}

type Manager[T Sessionable] struct {
	init func() T
}

func NewManager[T any, PT interface {
	Sessionable
	*T
}](name string, manager *Manager) *Manager[PT] {
	return &Manager[PT]{
		init: func() PT {
			return PT(new(T))
		},
	}
}

func (m *Manager[T]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sd, loaded, delete, err := m.loadSession(r)
		if err != nil && m.opts.FailOnSessionLoadError {
			m.opts.ErrorHandler(err, w, r)
			return
		}
		if !loaded {
			// either failed or loaded no cookie, init a new session.
			sd = PtrT(new(T))
		}

		sess := &session[T, PtrT]{
			data:   sd,
			delete: delete,
		}

		r = r.WithContext(context.WithValue(r.Context(), mgrCtxKey{}, m))
		r = r.WithContext(context.WithValue(r.Context(), mgrCtxKey{}, m))

		r = r.WithContext(context.WithValue(r.Context(), sessCtxKey{sessName: m.sessionName}, sess))
		hw := &hookRW{
			ResponseWriter: w,
			hook: func(w http.ResponseWriter) bool {
				if err := m.writeSession(w, sess); err != nil {
					m.opts.ErrorHandler(err, w, r)
					return false
				}
				return true
			},
		}

		next.ServeHTTP(hw, r)

		// if the handler doesn't write anything, make sure we fire the hook
		// anyway.
		hw.hookOnce.Do(func() {
			hw.hook(hw.ResponseWriter)
		})
	})
}

func (s *Manager[T]) Get(ctx context.Context) (_ T, exist bool) {
	sessCtx, ok := ctx.Value(sessCtxKey{}).(*sessCtx)
	if !ok {
		panic("context contained no or invalid session")
	}

	// TODO we actually need to try and load here
	d, ok := sessCtx.sessions[PT(new(T)).Type()]
	if !ok {
		return PT(new(T)), false, nil
	}

	return d.data.(PT), true, nil
}

func Save[T any, PT Sessionable[T]](ctx context.Context, sess PT) {

}

func Delete[T any, PT Sessionable[T]](ctx context.Context) {

}

func Reset[T any, PT Sessionable[T]](ctx context.Context, sess PT) {

}

func getSessMgr(ctx context.Context) (*sessCtx, *Manager) {
	return nil, nil
}
