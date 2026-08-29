package session

import (
	"context"

	"lds.li/session/internal/testsession"
)

// testSessionFromContext materializes the private sessiontest fixture attached
// for this manager. Keeping this bridge here leaves FromContext concerned only
// with selecting the session associated with a context.
func (m *Manager[T]) testSessionFromContext(ctx context.Context) (*Session[T], bool) {
	state, ok := testsession.FromContext[T](ctx, m)
	if !ok {
		return nil, false
	}
	if existing := state.Session(); existing != nil {
		return existing.(*Session[T]), true
	}
	return m.bindTestSession(state), true
}

func (m *Manager[T]) bindTestSession(state *testsession.State[T]) *Session[T] {
	initial := state.Initial()
	sess := m.newRequestSession()
	sess.isNew = initial.IsNew
	sess.loaded = true
	*sess.working = initial.Data
	for _, flash := range initial.Flashes {
		sess.meta.Flashes = append(sess.meta.Flashes, Flash{
			Level:   FlashLevel(flash.Level),
			Message: flash.Message,
		})
	}
	state.Bind(sess, func() testsession.Snapshot[T] {
		return snapshotTestSession(sess)
	})
	return sess
}

func snapshotTestSession[T any](sess *Session[T]) testsession.Snapshot[T] {
	flashes := make([]testsession.Flash, len(sess.meta.Flashes))
	for i, flash := range sess.meta.Flashes {
		flashes[i] = testsession.Flash{
			Level:   string(flash.Level),
			Message: flash.Message,
		}
	}
	return testsession.Snapshot[T]{
		Data:    *sess.working,
		Saved:   sess.dataScheduled,
		Deleted: sess.deleted,
		Reset:   sess.rotate,
		IsNew:   sess.isNew,
		Flashes: flashes,
	}
}
