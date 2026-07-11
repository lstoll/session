package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func newTestMAC(t *testing.T) tink.MAC {
	t.Helper()
	handle, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	prim, err := mac.New(handle)
	if err != nil {
		t.Fatal(err)
	}
	return prim
}

type countingKV struct {
	mu   sync.Mutex
	kv   *memoryKV
	gets int
	sets int
}

func (c *countingKV) Get(ctx context.Context, key string) ([]byte, bool, error) {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	return c.kv.Get(ctx, key)
}

func (c *countingKV) Set(ctx context.Context, key string, expiresAt time.Time, value []byte) error {
	c.mu.Lock()
	c.sets++
	c.mu.Unlock()
	return c.kv.Set(ctx, key, expiresAt, value)
}

func (c *countingKV) Delete(ctx context.Context, key string) error {
	return c.kv.Delete(ctx, key)
}

func (c *countingKV) getCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets
}

func (c *countingKV) setCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sets
}

func TestKVManager_SessionIDMAC_roundTrip(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	mgr, err := NewKVManager(kv, &KVManagerOpts{
		SessionIDMAC: newTestMAC(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := MustFromContext(r.Context())
		switch r.URL.Path {
		case "/set":
			sess.Set("user", "alice")
			w.WriteHeader(http.StatusOK)
		case "/get":
			if sess.Get("user") != "alice" {
				http.Error(w, "missing user", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))

	client := httptest.NewRecorder()
	reqSet := httptest.NewRequest(http.MethodGet, "/set", nil)
	handler.ServeHTTP(client, reqSet)
	if client.Code != http.StatusOK {
		t.Fatalf("set: %d", client.Code)
	}
	cookies := client.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	if !strings.HasPrefix(cookies[0].Value, managerMACSessionCookieMagic+".") {
		t.Fatalf("expected MAC-signed cookie, got %q", cookies[0].Value)
	}

	reqGet := httptest.NewRequest(http.MethodGet, "/get", nil)
	for _, c := range cookies {
		reqGet.AddCookie(c)
	}
	rrGet := httptest.NewRecorder()
	handler.ServeHTTP(rrGet, reqGet)
	if rrGet.Code != http.StatusOK {
		t.Fatalf("get: %d", rrGet.Code)
	}
}

func TestKVManager_SessionIDMAC_rejectsForgedCookie(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	mgr, err := NewKVManager(kv, &KVManagerOpts{
		SessionIDMAC: newTestMAC(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	forgedID := "FORGEDSESSIONIDFORGEDSESSIONIDFORGEDSE"
	forgedKey := managerHashSessionID(forgedID)

	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		MustFromContext(r.Context()).Set("k", "v")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: mgr.cookieSettings.Name, Value: forgedID})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if _, ok := kv.contents[forgedKey]; ok {
		t.Fatal("forged session id should not create KV entry at attacker-chosen key")
	}
	if len(kv.contents) != 1 {
		t.Fatalf("expected one server-issued session in KV, got %d", len(kv.contents))
	}
	for key := range kv.contents {
		if key == forgedKey {
			t.Fatal("KV key must not match forged session id hash")
		}
	}
}

func TestKVManager_SessionIDMAC_skipsKVGetOnInvalidCookie(t *testing.T) {
	ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
	mgr, err := NewKVManager(ckv, &KVManagerOpts{
		SessionIDMAC: newTestMAC(t),
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: mgr.cookieSettings.Name, Value: "MS1.not-a-real-id.not-a-real-tag"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if ckv.getCount() != 0 {
		t.Fatalf("invalid MAC cookie should not hit KV, got %d gets", ckv.getCount())
	}
}

func TestKVManager_withoutSessionIDMAC_acceptsBareCookie(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	mgr, err := NewKVManager(kv, nil)
	if err != nil {
		t.Fatal(err)
	}

	bareID := "BARESESSIONIDBARESESSIONIDBARESESS"
	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		MustFromContext(r.Context()).Set("k", "v")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: mgr.cookieSettings.Name, Value: bareID})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if _, ok := kv.contents[managerHashSessionID(bareID)]; !ok {
		t.Fatal("without MAC, bare cookie value is used as session id")
	}
}
