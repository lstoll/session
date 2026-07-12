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

func TestKVManager_LazyLoad_skipsKVWithoutSessionAccess(t *testing.T) {
	ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
	mgr, err := NewKVManager(ckv, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Seed a session directly in KV.
	seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgr.FromContext(r.Context()).Set("user", "alice")
		w.WriteHeader(http.StatusOK)
	}))
	rrSeed := httptest.NewRecorder()
	seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/seed", nil))
	cookies := rrSeed.Result().Cookies()
	if ckv.getCount() != 0 {
		t.Fatalf("seed without cookie should not hit KV, got %d gets", ckv.getCount())
	}
	if ckv.setCount() != 1 {
		t.Fatalf("seed save should write KV once, got %d sets", ckv.setCount())
	}

	static := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("static"))
	}))
	rrStatic := httptest.NewRecorder()
	reqStatic := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	for _, c := range cookies {
		reqStatic.AddCookie(c)
	}
	static.ServeHTTP(rrStatic, reqStatic)
	if rrStatic.Code != http.StatusOK {
		t.Fatalf("static: %d", rrStatic.Code)
	}
	if ckv.getCount() != 0 {
		t.Fatalf("static request should not hit KV, got %d gets", ckv.getCount())
	}
	if ckv.setCount() != 1 {
		t.Fatalf("static request should not touch KV, got %d sets", ckv.setCount())
	}
}

func TestKVManager_LazyLoad_loadsOnSessionAccess(t *testing.T) {
	ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
	mgr, err := NewKVManager(ckv, nil)
	if err != nil {
		t.Fatal(err)
	}

	seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgr.FromContext(r.Context()).Set("user", "alice")
	}))
	rrSeed := httptest.NewRecorder()
	seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/seed", nil))
	cookies := rrSeed.Result().Cookies()

	app := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mgr.FromContext(r.Context()).Get("user") != "alice" {
			http.Error(w, "missing user", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	rrApp := httptest.NewRecorder()
	reqApp := httptest.NewRequest(http.MethodGet, "/me", nil)
	for _, c := range cookies {
		reqApp.AddCookie(c)
	}
	app.ServeHTTP(rrApp, reqApp)
	if rrApp.Code != http.StatusOK {
		t.Fatalf("app: %d", rrApp.Code)
	}
	if ckv.getCount() != 1 {
		t.Fatalf("expected load on session access, got %d gets", ckv.getCount())
	}
}

func TestKVManager_EagerLoad_hitsKVOnEveryRequest(t *testing.T) {
	ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
	mgr, err := NewKVManager(ckv, &KVManagerOpts{EagerLoad: true})
	if err != nil {
		t.Fatal(err)
	}

	seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgr.FromContext(r.Context()).Set("user", "alice")
	}))
	rrSeed := httptest.NewRecorder()
	seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/seed", nil))
	cookies := rrSeed.Result().Cookies()

	static := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rrStatic := httptest.NewRecorder()
	reqStatic := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	for _, c := range cookies {
		reqStatic.AddCookie(c)
	}
	static.ServeHTTP(rrStatic, reqStatic)
	if ckv.getCount() != 1 {
		t.Fatalf("eager load should hit KV on cookie-bearing request, got %d gets", ckv.getCount())
	}
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
		sess := mgr.FromContext(r.Context())
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
		mgr.FromContext(r.Context()).Set("k", "v")
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

func TestKVManager_withoutSessionIDMAC_replacesUnknownBareCookie(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	mgr, err := NewKVManager(kv, nil)
	if err != nil {
		t.Fatal(err)
	}

	bareID := "AAAAAAAAAAAAAAAAAAAAAAAAAA"
	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgr.FromContext(r.Context()).Set("k", "v")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: mgr.cookieSettings.Name, Value: bareID})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if _, ok := kv.contents[managerHashSessionID(bareID)]; ok {
		t.Fatal("unknown client-provided ID must not be adopted")
	}
	if len(kv.contents) != 1 {
		t.Fatalf("expected one server-issued session, got %d", len(kv.contents))
	}
	issued := rr.Result().Cookies()
	if len(issued) != 1 || issued[0].Value == bareID {
		t.Fatalf("server did not replace unknown ID: %#v", issued)
	}
}

func TestKVManager_withoutSessionIDMAC_skipsOversizedIDLookup(t *testing.T) {
	ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
	mgr, err := NewKVManager(ckv, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgr.FromContext(r.Context()).Set("k", "v")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: mgr.cookieSettings.Name, Value: strings.Repeat("x", 129)})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if ckv.getCount() != 0 {
		t.Fatalf("oversized ID should not hit KV, got %d gets", ckv.getCount())
	}
}

func TestSession_IsNew(t *testing.T) {
	t.Run("lazy until loaded", func(t *testing.T) {
		ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
		mgr, err := NewKVManager(ckv, nil)
		if err != nil {
			t.Fatal(err)
		}

		var cookies []*http.Cookie
		seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := mgr.FromContext(r.Context())
			if !sess.IsNew() {
				t.Fatal("first visit should be new")
			}
			sess.Set("user", "alice")
		}))
		rrSeed := httptest.NewRecorder()
		seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/seed", nil))
		cookies = rrSeed.Result().Cookies()

		static := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !mgr.FromContext(r.Context()).IsNew() {
				t.Fatal("lazy static route should stay new without session access")
			}
		}))
		reqStatic := httptest.NewRequest(http.MethodGet, "/static", nil)
		for _, c := range cookies {
			reqStatic.AddCookie(c)
		}
		rrStatic := httptest.NewRecorder()
		static.ServeHTTP(rrStatic, reqStatic)

		load := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := mgr.FromContext(r.Context())
			if sess.Get("user") != "alice" {
				t.Fatalf("got %v", sess.Get("user"))
			}
			if sess.IsNew() {
				t.Fatal("returning visit should not be new after load")
			}
		}))
		reqLoad := httptest.NewRequest(http.MethodGet, "/load", nil)
		for _, c := range cookies {
			reqLoad.AddCookie(c)
		}
		rrLoad := httptest.NewRecorder()
		load.ServeHTTP(rrLoad, reqLoad)
	})

	t.Run("eager returning visit", func(t *testing.T) {
		kv := &memoryKV{contents: make(map[string]kvItem)}
		mgr, err := NewKVManager(kv, &KVManagerOpts{EagerLoad: true})
		if err != nil {
			t.Fatal(err)
		}

		var cookies []*http.Cookie
		seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mgr.FromContext(r.Context()).Set("k", "v")
		}))
		rrSeed := httptest.NewRecorder()
		seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/", nil))
		cookies = rrSeed.Result().Cookies()

		returning := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mgr.FromContext(r.Context()).IsNew() {
				t.Fatal("eager load should restore existing session")
			}
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		returning.ServeHTTP(rr, req)
	})

	t.Run("reset", func(t *testing.T) {
		kv := &memoryKV{contents: make(map[string]kvItem)}
		mgr, err := NewKVManager(kv, &KVManagerOpts{EagerLoad: true})
		if err != nil {
			t.Fatal(err)
		}

		var cookies []*http.Cookie
		seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mgr.FromContext(r.Context()).Set("k", "v")
		}))
		rrSeed := httptest.NewRecorder()
		seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/", nil))
		cookies = rrSeed.Result().Cookies()

		reset := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := mgr.FromContext(r.Context())
			if sess.IsNew() {
				t.Fatal("loaded session should not be new")
			}
			sess.Reset()
			if !sess.IsNew() {
				t.Fatal("reset should mark session new")
			}
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		reset.ServeHTTP(rr, req)
	})
}
