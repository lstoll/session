// Package testsession provides the private bridge between session and
// sessiontest. It is internal so applications cannot attach sessions without
// going through the testing.TB-guarded public helper.
package testsession

import "context"

type contextKey[T any] struct {
	manager any
}

// Flash identifies the flash state of an attached test session.
type Flash uint8

const (
	FlashNone Flash = iota
	FlashMessage
	FlashError
)

// Initial describes a session attached by sessiontest.
type Initial[T any] struct {
	Data         T
	IsNew        bool
	Flash        Flash
	FlashMessage string
}

// Snapshot describes the current state of an attached session.
type Snapshot[T any] struct {
	Data         T
	Saved        bool
	Deleted      bool
	Reset        bool
	IsNew        bool
	Flash        Flash
	FlashMessage string
}

// State connects an attached request to the session created by Manager.
type State[T any] struct {
	initial  Initial[T]
	session  any
	snapshot func() Snapshot[T]
}

// WithContext attaches initial test state for manager to ctx.
func WithContext[T any](ctx context.Context, manager any, initial Initial[T]) (context.Context, *State[T]) {
	state := &State[T]{initial: initial}
	return context.WithValue(ctx, contextKey[T]{manager: manager}, state), state
}

// FromContext returns test state attached for manager.
func FromContext[T any](ctx context.Context, manager any) (*State[T], bool) {
	state, ok := ctx.Value(contextKey[T]{manager: manager}).(*State[T])
	return state, ok
}

// Initial returns the state used to construct the request-scoped session.
func (s *State[T]) Initial() Initial[T] { return s.initial }

// Session returns the request-scoped session previously bound by Manager.
func (s *State[T]) Session() any { return s.session }

// Bind connects the request-scoped session and its snapshot function.
func (s *State[T]) Bind(session any, snapshot func() Snapshot[T]) {
	s.session = session
	s.snapshot = snapshot
}

// Snapshot returns the current state, or the initial state before the manager
// has accessed the attached session.
func (s *State[T]) Snapshot() Snapshot[T] {
	if s.snapshot != nil {
		return s.snapshot()
	}
	return Snapshot[T]{
		Data:         s.initial.Data,
		IsNew:        s.initial.IsNew,
		Flash:        s.initial.Flash,
		FlashMessage: s.initial.FlashMessage,
	}
}
