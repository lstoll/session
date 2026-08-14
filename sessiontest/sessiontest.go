// Package sessiontest provides helpers for unit testing handlers that use
// package session.
package sessiontest

import (
	"net/http"
	"testing"

	"lds.li/session"
	"lds.li/session/internal/testsession"
)

type config struct {
	isNew        bool
	flash        testsession.Flash
	flashMessage string
}

// Option configures a session attached by WithSession. Only options provided
// by this package are supported.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(config *config) { f(config) }

// WithFlashMessage attaches an informational flash message.
func WithFlashMessage(message string) Option {
	return optionFunc(func(config *config) {
		config.flash = testsession.FlashMessage
		config.flashMessage = message
	})
}

// WithFlashError attaches an error flash message.
func WithFlashError(message string) Option {
	return optionFunc(func(config *config) {
		config.flash = testsession.FlashError
		config.flashMessage = message
	})
}

// AsNewSession makes the attached session report IsNew as true. Sessions with
// initial data are treated as existing by default.
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

// Saved reports whether the session was marked for saving.
func (c *Change[T]) Saved() bool { return c.state.Snapshot().Saved }

// Deleted reports whether the session was marked for deletion.
func (c *Change[T]) Deleted() bool { return c.state.Snapshot().Deleted }

// Reset reports whether the session was marked for renewal.
func (c *Change[T]) Reset() bool { return c.state.Snapshot().Reset }

// IsNew reports the session's current IsNew state.
func (c *Change[T]) IsNew() bool { return c.state.Snapshot().IsNew }

// HasFlash reports whether the session currently contains a flash message.
func (c *Change[T]) HasFlash() bool { return c.state.Snapshot().Flash != testsession.FlashNone }

// FlashIsError reports whether the current flash message is an error.
func (c *Change[T]) FlashIsError() bool {
	return c.state.Snapshot().Flash == testsession.FlashError
}

// FlashMessage returns the current flash message without consuming it.
func (c *Change[T]) FlashMessage() string { return c.state.Snapshot().FlashMessage }

// WithSession attaches a session to request for a unit test. The returned
// request must be passed to the code under test. Change reflects mutations made
// through manager.FromContext. WithSession does not run the manager middleware
// or persist the resulting session.
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

	ctx, state := testsession.WithContext(request.Context(), manager, testsession.Initial[T]{
		Data:         data,
		IsNew:        config.isNew,
		Flash:        config.flash,
		FlashMessage: config.flashMessage,
	})
	return request.WithContext(ctx), &Change[T]{state: state}
}
