package session

import (
	"context"
	"time"
)

// TestResult reports how a session changed while using TestContext.
type TestResult[T any] struct {
	session *Session[T]
}

// Saved reports whether the session was marked for saving.
func (t *TestResult[T]) Saved() bool {
	return t.session.state == sessionDirty
}

// Deleted reports whether the session was marked for deletion.
func (t *TestResult[T]) Deleted() bool {
	return t.session.state == sessionDeleted
}

// Reset reports whether the session was marked for renewal.
func (t *TestResult[T]) Reset() bool {
	return t.session.rotate
}

// Result returns the session's current application data.
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
