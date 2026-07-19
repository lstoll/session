package session

import (
	"context"
	"time"
)

type TestResult[T any] struct {
	ctx *Session[T]
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
	return t.ctx.sessdata.Data
}

// TestContext attaches a session containing data to a context for testing.
// The returned TestResult can be used to verify actions against the session.
func (m *Manager[T]) TestContext(ctx context.Context, data T) (context.Context, *TestResult[T]) {
	s := &Session[T]{
		mgr:   m,
		isNew: true,
		sessdata: persistedSession[T]{
			Data:      data,
			CreatedAt: time.Now(),
		},
	}
	return context.WithValue(ctx, sessionContextKey[T]{manager: m}, s), &TestResult[T]{ctx: s}
}
