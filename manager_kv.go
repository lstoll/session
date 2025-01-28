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

type KVManager[T any] struct {
	manager *manager[T]
}

func NewKVManager[T any, PtrT interface {
	*T
}](kv KV) *KVManager[PtrT] {
	s := &kvStore{
		KV: kv,
	}
	return &KVManager[PtrT]{
		manager: newManager[T, PtrT](s),
	}
}

func NewMemoryManager[T any, PtrT interface {
	*T
}]() *KVManager[PtrT] {
	return NewKVManager[T, PtrT](&memoryKV{
		contents: make(map[string]kvItem),
	})
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
