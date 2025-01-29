package session

import (
	"context"
	"time"
)

func ContextWithSession[T any](mgr interface {
	getManagerInstance() *manager[T]
}, ctx context.Context, sess T, loaded bool) context.Context {
	return context.WithValue(ctx, mgrSessCtxKey[T]{inst: mgr.getManagerInstance()}, &sessCtx[T]{
		metadata: &sessionMetadata{
			CreatedAt: time.Now(),
		},
		loaded: loaded,
		data:   sess,
	})
}
