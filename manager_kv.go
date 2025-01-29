package session

import (
	"context"
	"net/http"
	"time"
)

type KV interface {
	Get(_ context.Context, key string) (_ []byte, found bool, _ error)
	Set(_ context.Context, key string, expiresAt time.Time, value []byte) error
	Delete(_ context.Context, key string) error
}

const (
	DefaultExpiraton    = 24 * time.Hour
	DefaultKVCookieName = "session-id"
)

var (
	DefaultKVCookieOpts = &CookieOpts{
		Name: "session-id",
	}
)

type KVManagerOpts struct {
	// Expiration is the time passed to the storage, after which the session
	// data should no longer be considered valid. This will be extended every
	// time the session is written to/reset. Defaults to DefaultExpiraton. This
	// does not affect the tracking cookie lifetime, which can be customized via
	// CookieOpts.
	Expiration time.Duration
	// CookieOpts can be used to manage the cookie the session ID is tracked in.
	// If not set, DefaultKVCookieName will be used for the name.
	CookieOpts *CookieOpts
}

type KVManager[T any] struct {
	manager *manager[T]
}

func NewKVManager[T any, PtrT interface {
	*T
}](kv KV, opts *KVManagerOpts) *KVManager[PtrT] {
	s := &kvStore{
		kv:         kv,
		cookieOpts: DefaultKVCookieOpts,
	}
	mgropts := &managerOpts{
		expiry: defaultMaxAge,
	}
	if opts != nil {
		if opts.Expiration == 0 {
			mgropts.expiry = opts.Expiration
		}
		if opts.CookieOpts != nil {
			s.cookieOpts = opts.CookieOpts
		}

	}
	return &KVManager[PtrT]{
		manager: newManager[T, PtrT](s, mgropts),
	}
}

func NewMemoryManager[T any, PtrT interface {
	*T
}](opts *KVManagerOpts) *KVManager[PtrT] {
	return NewKVManager[T, PtrT](&memoryKV{
		contents: make(map[string]kvItem),
	}, opts)
}

func (k *KVManager[T]) Wrap(next http.Handler) http.Handler {
	return k.manager.wrap(next)
}

func (k *KVManager[T]) Get(ctx context.Context) (_ T, exist bool) {
	return k.manager.get(ctx)
}

func (k *KVManager[T]) Save(ctx context.Context, sess T) {
	k.manager.save(ctx, sess)
}

func (k *KVManager[T]) Delete(ctx context.Context) {
	k.manager.delete(ctx)
}

func (k *KVManager[T]) Reset(ctx context.Context, sess T) {
	k.manager.reset(ctx, sess)
}

//nolint:unused // used by the test context helper
func (k *KVManager[T]) getManagerInstance() *manager[T] {
	return k.manager
}
