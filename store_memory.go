package session

import (
	"context"
	"sync"
)

type memoryKV struct {
	contents   map[string][]byte
	contentsMu sync.RWMutex
}

func (m *memoryKV) Get(_ context.Context, key string) (_ []byte, found bool, _ error) {
	m.contentsMu.RLock()
	defer m.contentsMu.RUnlock()

	v, ok := m.contents[key]
	return v, ok, nil
}

func (m *memoryKV) Set(_ context.Context, key string, value []byte) error {
	m.contentsMu.Lock()
	defer m.contentsMu.Unlock()

	m.contents[key] = value
	return nil
}

func (m *memoryKV) Delete(_ context.Context, key string) error {
	m.contentsMu.Lock()
	defer m.contentsMu.Unlock()

	delete(m.contents, key)
	return nil
}

func NewMemoryStore() *KVStore {
	return &KVStore{
		KV: &memoryKV{
			contents: make(map[string][]byte),
		},
	}
}
