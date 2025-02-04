package session

import (
	"context"
	"time"
)

func ContextWithSession[T any](mgr *Manager[T], ctx context.Context, sess T) context.Context {
	return context.WithValue(ctx, mgrSessCtxKey[T]{inst: mgr}, &sessCtx[T]{
		metadata: &sessionMetadata{
			CreatedAt: time.Now(),
		},
		data: sess,
	})
}
