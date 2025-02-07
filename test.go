package session

import (
	"context"
	"time"
)

type TestResult[T any] struct {
	ctx *sessCtx[T]
}

func (t *TestResult[T]) Saved() bool {
	return t.ctx.save
}

func (t *TestResult[T]) Deleted() bool {
	return t.ctx.delete
}

func (t *TestResult[T]) Reset() bool {
	return t.ctx.reset
}

func (t *TestResult[T]) Result() T {
	return t.ctx.data
}

// TestContext attaches a session to a context, to be used for testing. The
// returned TestResult can be used to verify the actions against the session
func TestContext[T any](mgr *Manager[T], ctx context.Context, sess T) (context.Context, *TestResult[T]) {
	return context.WithValue(ctx, mgrSessCtxKey[T]{inst: mgr}, &sessCtx[T]{
		metadata: &sessionMetadata{
			CreatedAt: time.Now(),
		},
		data: sess,
	}), nil
}
