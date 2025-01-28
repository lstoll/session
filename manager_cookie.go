package session

import (
	"context"
	"net/http"
)

type CookieManagerOpts struct{}

type CookieManager[T any] struct {
	manager *manager[T]
}

func NewCookieManager[T any, PtrT interface {
	*T
}](aead AEAD, opts *CookieManagerOpts) *CookieManager[PtrT] {
	s := &cookieStore{
		AEAD:           aead,
		CookieTemplate: DefaultCookieTemplate,
	}
	s.CookieTemplate.Name = "session"
	return &CookieManager[PtrT]{
		manager: newManager[T, PtrT](s),
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
