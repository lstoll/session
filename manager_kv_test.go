package session

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestAuthenticator(t *testing.T, current byte, previous ...byte) Authenticator {
	t.Helper()
	previousKeys := make([][]byte, len(previous))
	for i, value := range previous {
		previousKeys[i] = bytes.Repeat([]byte{value}, 32)
	}
	authenticator, err := NewHMACSHA256Authenticator(bytes.Repeat([]byte{current}, 32), previousKeys...)
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

type failingGetKV struct{}

func (failingGetKV) Get(context.Context, string) ([]byte, bool, error) {
	return nil, false, errors.New("store unavailable")
}
func (failingGetKV) Set(context.Context, string, time.Time, []byte) error { return nil }
func (failingGetKV) Delete(context.Context, string) error                 { return nil }

type countingKV struct {
	mu   sync.Mutex
	kv   *memoryKV
	gets int
	sets int
}

func TestMemoryKVConcurrentExpiredReads(t *testing.T) {
	kv := NewMemoryKV()
	if err := kv.Set(context.Background(), "expired", time.Now().Add(-time.Second), []byte("value")); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, found, err := kv.Get(context.Background(), "expired"); err != nil || found {
				t.Errorf("Get = found %v, err %v", found, err)
			}
		})
	}
	wg.Wait()
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
	mgr, err := NewKVManager[testSessionData](ckv, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Seed a session directly in KV.
	seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setTestUser(mgr.FromContext(r.Context()), "alice")
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
	mgr, err := NewKVManager[testSessionData](ckv, nil)
	if err != nil {
		t.Fatal(err)
	}

	seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setTestUser(mgr.FromContext(r.Context()), "alice")
	}))
	rrSeed := httptest.NewRecorder()
	seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/seed", nil))
	cookies := rrSeed.Result().Cookies()

	app := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mgr.FromContext(r.Context()).Get().User != "alice" {
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
	mgr, err := NewKVManager[testSessionData](ckv, &KVManagerOpts[testSessionData]{EagerLoad: true})
	if err != nil {
		t.Fatal(err)
	}

	seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setTestUser(mgr.FromContext(r.Context()), "alice")
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

func TestKVManager_LoadErrorAbortsRequest(t *testing.T) {
	for _, eager := range []bool{false, true} {
		t.Run(map[bool]string{false: "lazy", true: "eager"}[eager], func(t *testing.T) {
			var handled error
			mgr, err := NewKVManager[testSessionData](failingGetKV{}, &KVManagerOpts[testSessionData]{
				EagerLoad: eager,
				ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
					handled = err
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
				},
			})

			if err != nil {
				t.Fatal(err)
			}

			called := false
			handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				mgr.FromContext(r.Context()).Get()
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: mgr.cookieSettings.Name, Value: "AAAAAAAAAAAAAAAAAAAAAAAAAA"})
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if eager && called {
				t.Fatal("eager load error must prevent handler execution")
			}
			if !eager && !called {
				t.Fatal("lazy handler must run until session access triggers loading")
			}
			if handled == nil || !strings.Contains(handled.Error(), "store unavailable") {
				t.Fatalf("ErrorHandler received %v", handled)
			}
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", rr.Code)
			}
		})
	}
}

func TestKVManager_replacesUnknownCookie(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	mgr, err := NewKVManager[testSessionData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}

	bareID := "AAAAAAAAAAAAAAAAAAAAAAAAAA"
	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setTestUser(mgr.FromContext(r.Context()), "v")
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

func TestKVManager_SessionIDAuthenticatorRotation(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	oldManager, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{
		SessionIDAuthenticator: newTestAuthenticator(t, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	seed := oldManager.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setTestUser(oldManager.FromContext(r.Context()), "alice")
	}))
	seedResponse := httptest.NewRecorder()
	seed.ServeHTTP(seedResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	cookies := seedResponse.Result().Cookies()
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0].Value, managerAuthenticatedSessionCookieMagic+".") {
		t.Fatalf("authenticated session cookie = %#v", cookies)
	}

	rotatedManager, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{
		SessionIDAuthenticator: newTestAuthenticator(t, 2, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	load := rotatedManager.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := rotatedManager.FromContext(r.Context()).Get().User; got != "alice" {
			t.Fatalf("loaded user = %q, want alice", got)
		}
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookies[0])
	load.ServeHTTP(httptest.NewRecorder(), request)
}

func TestKVManager_InvalidAuthenticatorSkipsLookup(t *testing.T) {
	ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
	mgr, err := NewKVManager[testSessionData](ckv, &KVManagerOpts[testSessionData]{
		SessionIDAuthenticator: newTestAuthenticator(t, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgr.FromContext(r.Context()).Get()
	}))
	for _, value := range []string{
		managerAuthenticatedSessionCookieMagic + ".id.invalid",
		managerAuthenticatedSessionCookieMagic + ".id." + strings.Repeat("x", managerMaxCookieSize),
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(&http.Cookie{Name: mgr.cookieSettings.Name, Value: value})
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	if ckv.getCount() != 0 {
		t.Fatalf("invalid authenticator caused %d KV lookups", ckv.getCount())
	}
}

func TestKVManager_skipsOversizedIDLookup(t *testing.T) {
	ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
	mgr, err := NewKVManager[testSessionData](ckv, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setTestUser(mgr.FromContext(r.Context()), "v")
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
		mgr, err := NewKVManager[testSessionData](ckv, nil)
		if err != nil {
			t.Fatal(err)
		}

		var cookies []*http.Cookie
		seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := mgr.FromContext(r.Context())
			if !sess.IsNew() {
				t.Fatal("first visit should be new")
			}
			setTestUser(sess, "alice")
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
			if sess.Get().User != "alice" {
				t.Fatalf("got %v", sess.Get().User)
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
		mgr, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{EagerLoad: true})
		if err != nil {
			t.Fatal(err)
		}

		var cookies []*http.Cookie
		seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setTestUser(mgr.FromContext(r.Context()), "v")
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
		mgr, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{EagerLoad: true})
		if err != nil {
			t.Fatal(err)
		}

		var cookies []*http.Cookie
		seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setTestUser(mgr.FromContext(r.Context()), "v")
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
