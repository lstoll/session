package session

import (
	"context"
	"errors"
	"net/http"
)

type Sessionable interface {
	// // New is called on a nil pointer of this type. It should construct a new
	// // instance of the session type, for when a session is initialized. It can
	// // be used to set any defaults.
	// New() Sessionable
	// SessionName returns a unique name for this session type. It should be
	// constant, and may be called with a nil self.
	SessionName() string
	SessionValid() bool
}

// Auto is used to automatically manage a strongly types session. It wraps
// handlers, and loads/saves the session type as needed. It provides methods to
// interact with the session.
type Auto[T Sessionable] struct {
	Store Store

	newEmpty func() T
}

func (a *Auto[T]) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessData := DefaultMarshaler.NewMap()
		_, err := a.Store.Get(r, &sessData)
		if err != nil {
			// m.opts.ErrorHandler(w, r, err)
			return
		}

		sess := a.newEmpty()
		if err := sessData.Unmarshal(sess.SessionName(), sess); err != nil {
			if !errors.Is(err, errKeyNotFound) {
				// HANDLE
				return
			}
			// ok, continue with the empty
		}
		// TODO - check if we found data or not

		ctxsess := &sessCtx[T]{}
		if sess.SessionValid() {
			ctxsess.data = sess
		} else {
			ctxsess.data = a.newEmpty()
			ctxsess.delete = true
		}

		r = r.WithContext(context.WithValue(r.Context(), sessCtxKey{name: sess.SessionName()}, ctxsess))

		hw := &hookRW{
			ResponseWriter: w,
			hook: func(w http.ResponseWriter) bool {

				// if err := m.store.PutSession(r.Context(), w, r, m.name, "TODO", sess.data); err != nil {
				// 	m.opts.ErrorHandler(w, r, err)
				// 	return false
				// }
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

func (a *Auto[T]) Get(ctx context.Context) (_ T, exist bool) {
	// sessCtx, ok := ctx.Value(sessCtxKey{}).(*sessCtx)
	// if !ok {
	// 	panic("context contained no or invalid session")
	// }

	t := a.newEmpty()
	// return new(T), nil
	return t, false
}

func (a *Auto[T]) Save(ctx context.Context, sess T) {

}

func (a *Auto[T]) Delete(ctx context.Context) {

}

func (a *Auto[T]) Reset(ctx context.Context, sess T) {

}
