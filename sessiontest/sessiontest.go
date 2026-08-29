// Package sessiontest provides fixtures for handlers that use package session.
package sessiontest

import (
	"net/http"
	"testing"

	"lds.li/session"
	"lds.li/session/internal/testsession"
)

type config struct {
	isNew   bool
	flashes []session.Flash
}

// Option configures a session attached by WithSession. Options are created by
// this package.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(config *config) { f(config) }

// WithFlash adds a flash to the attached session.
func WithFlash(flash session.Flash) Option {
	return optionFunc(func(config *config) {
		config.flashes = append(config.flashes, flash)
	})
}

// WithFlashMessage adds an informational flash message to the attached session.
func WithFlashMessage(message string) Option {
	return WithFlash(session.Flash{
		Level:   session.FlashLevelInfo,
		Message: message,
	})
}

// WithFlashError adds an error flash message to the attached session.
func WithFlashError(message string) Option {
	return WithFlash(session.Flash{
		Level:   session.FlashLevelError,
		Message: message,
	})
}

// AsNewSession makes the attached session report IsNew.
func AsNewSession() Option {
	return optionFunc(func(config *config) {
		config.isNew = true
	})
}

// Change reports the current state of a session attached by WithSession.
type Change[T any] struct {
	state *testsession.State[T]
}

// Data returns the session's current application data.
func (c *Change[T]) Data() T { return c.state.Snapshot().Data }

// Saved reports whether Save or Reset was called. Metadata-only changes do not
// set Saved.
func (c *Change[T]) Saved() bool { return c.state.Snapshot().Saved }

// Deleted reports whether the session was marked for deletion.
func (c *Change[T]) Deleted() bool { return c.state.Snapshot().Deleted }

// Reset reports whether the session was marked for renewal.
func (c *Change[T]) Reset() bool { return c.state.Snapshot().Reset }

// IsNew reports the session's current IsNew state.
func (c *Change[T]) IsNew() bool { return c.state.Snapshot().IsNew }

// Flashes returns a copy of the session's current flash queue.
func (c *Change[T]) Flashes() []session.Flash {
	snapshot := c.state.Snapshot()
	flashes := make([]session.Flash, len(snapshot.Flashes))
	for i, flash := range snapshot.Flashes {
		flashes[i] = session.Flash{
			Level:   session.FlashLevel(flash.Level),
			Message: flash.Message,
		}
	}
	return flashes
}

// WithSession attaches a fixture to request and returns a Change that tracks
// session operations. The fixture also passes through Manager.Wrap without
// accessing production storage or cookies.
func WithSession[T any](
	t testing.TB,
	request *http.Request,
	manager *session.Manager[T],
	data T,
	options ...Option,
) (*http.Request, *Change[T]) {
	t.Helper()
	if request == nil {
		t.Fatal("sessiontest: request is nil")
		return nil, nil
	}
	if manager == nil {
		t.Fatal("sessiontest: manager is nil")
		return nil, nil
	}

	config := config{}
	for _, option := range options {
		if option == nil {
			t.Fatal("sessiontest: option is nil")
			return nil, nil
		}
		option.apply(&config)
	}

	flashes := make([]testsession.Flash, len(config.flashes))
	for i, flash := range config.flashes {
		flashes[i] = testsession.Flash{
			Level:   string(flash.Level),
			Message: flash.Message,
		}
	}
	ctx, state := testsession.WithContext(request.Context(), manager, testsession.Initial[T]{
		Data:    data,
		IsNew:   config.isNew,
		Flashes: flashes,
	})
	return request.WithContext(ctx), &Change[T]{state: state}
}
