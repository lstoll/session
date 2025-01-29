package session

import (
	"context"
	"net/http"
	"time"
)

var DefaultCookieManagerCookieOpts = &CookieOpts{
	Name: "session",
}

const DefaultCookieSessionExpiration = 24 * time.Hour

type CookieManagerOpts struct {
	// Expiration sets the time an individual cookie is considered valid for,
	// before it is discarded. This is reset on any session save.
	Expiration time.Duration
	// CookieOpts can be used to manage the cookie the session is tracked in.
	// If not set, DefaultCookieManagerCookieOpts will be used for the name.
	CookieOpts *CookieOpts
}

type CookieManager[T any] struct {
	manager *manager[T]
}

func NewCookieManager[T any, PtrT interface {
	*T
}](aead AEAD, opts *CookieManagerOpts) *CookieManager[PtrT] {
	s := &cookieStore{
		AEAD:       aead,
		cookieOpts: DefaultCookieManagerCookieOpts,
	}
	mgropts := &managerOpts{
		expiry: DefaultCookieSessionExpiration,
	}
	if opts != nil {
		if opts.Expiration != 0 {
			mgropts.expiry = opts.Expiration
		}
		if opts.CookieOpts != nil {
			s.cookieOpts = opts.CookieOpts
		}
	}
	return &CookieManager[PtrT]{
		manager: newManager[T, PtrT](s, mgropts),
	}
}

func (c *CookieManager[T]) Wrap(next http.Handler) http.Handler {
	return c.manager.wrap(next)
}

func (c *CookieManager[T]) Get(ctx context.Context) (_ T, exist bool) {
	return c.manager.get(ctx)
}

func (c *CookieManager[T]) Save(ctx context.Context, sess T) {
	c.manager.save(ctx, sess)
}

func (c *CookieManager[T]) Delete(ctx context.Context) {
	c.manager.delete(ctx)
}
