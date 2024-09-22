package session

import (
	"context"
	"time"
)

type Sessionable[T any] interface {
	Type() string
	NotAfter() time.Time

	*T
}

func Load[T any, PT Sessionable[T]](ctx context.Context) (_ PT, exist bool, _ error) {
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
