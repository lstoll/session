package session

import (
	"context"
	"time"
)

type TestResult[T any] struct {
	session *Session[T]
}

func (t *TestResult[T]) Saved() bool {
	return t.session.state == sessionDirty
}

func (t *TestResult[T]) Deleted() bool {
	return t.session.state == sessionDeleted
}

func (t *TestResult[T]) Reset() bool {
	return t.session.rotate
}

func (t *TestResult[T]) Result() T {
	return t.session.sessdata.Data
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
	return context.WithValue(ctx, sessionContextKey[T]{manager: m}, s), &TestResult[T]{session: s}
}
