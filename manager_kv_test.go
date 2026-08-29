package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type snapshotErrorData struct {
	Value string `json:"value"`
}

func (d *snapshotErrorData) MarshalJSON() ([]byte, error) {
	if d.Value == "fail" {
		return nil, errors.New("snapshot failed")
	}
	type plain snapshotErrorData
	return json.Marshal((*plain)(d))
}

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

func TestMemoryKVCopiesValues(t *testing.T) {
	kv := NewMemoryKV()
	input := []byte("original")
	if err := kv.Set(context.Background(), "key", time.Now().Add(time.Hour), input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'

	first, found, err := kv.Get(context.Background(), "key")
	if err != nil || !found {
		t.Fatalf("first Get = found %v, err %v", found, err)
	}
	if string(first) != "original" {
		t.Fatalf("stored value changed through Set input: %q", first)
	}
	first[0] = 'Y'

	second, found, err := kv.Get(context.Background(), "key")
	if err != nil || !found {
		t.Fatalf("second Get = found %v, err %v", found, err)
	}
	if string(second) != "original" {
		t.Fatalf("stored value changed through Get result: %q", second)
	}
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
		saveTestUser(mgr.FromContext(r.Context()), "alice")
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
		saveTestUser(mgr.FromContext(r.Context()), "alice")
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
		saveTestUser(mgr.FromContext(r.Context()), "alice")
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
		saveTestUser(mgr.FromContext(r.Context()), "v")
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
		saveTestUser(oldManager.FromContext(r.Context()), "alice")
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
		managerAuthenticatedSessionCookieMagic + ".id." + strings.Repeat("x", managerMaxSetCookieSize),
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
		saveTestUser(mgr.FromContext(r.Context()), "v")
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
			saveTestUser(sess, "alice")
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
			saveTestUser(mgr.FromContext(r.Context()), "v")
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
			saveTestUser(mgr.FromContext(r.Context()), "v")
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

func TestKVManager_OnloadUseTransformsInMemoryOnly(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	mgr, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{
		Onload: func(data *testSessionData) (OnloadAction, error) {
			data.User = "onload-" + data.User
			return OnloadUse, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saveTestUser(mgr.FromContext(r.Context()), "alice")
		w.WriteHeader(http.StatusOK)
	}))
	rrSeed := httptest.NewRecorder()
	seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/seed", nil))
	cookies := rrSeed.Result().Cookies()

	var got *testSessionData
	read := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		got = sess.Get()
		sess.AddFlash(Flash{Message: "metadata write"})
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/read", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	read.ServeHTTP(httptest.NewRecorder(), req)
	if got.User != "onload-alice" {
		t.Fatalf("Get().User = %q, want onload-alice", got.User)
	}

	plain, err := NewKVManager[testSessionData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored := plain.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := plain.FromContext(r.Context())
		if got := sess.Get().User; got != "alice" {
			t.Fatalf("stored user = %q, want alice", got)
		}
		if flashes := sess.TakeFlashes(); len(flashes) != 1 || flashes[0].Message != "metadata write" {
			t.Fatalf("stored flashes = %#v", flashes)
		}
	}))
	reqStored := httptest.NewRequest(http.MethodGet, "/stored", nil)
	for _, c := range cookies {
		reqStored.AddCookie(c)
	}
	stored.ServeHTTP(httptest.NewRecorder(), reqStored)
}

func TestKVManager_OnloadDeleteDeletesSession(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	mgr, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{
		Onload: func(*testSessionData) (OnloadAction, error) {
			return OnloadDelete, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	seed := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saveTestUser(mgr.FromContext(r.Context()), "alice")
		w.WriteHeader(http.StatusOK)
	}))
	rrSeed := httptest.NewRecorder()
	seed.ServeHTTP(rrSeed, httptest.NewRequest(http.MethodGet, "/seed", nil))
	cookies := rrSeed.Result().Cookies()
	if len(kv.contents) != 1 {
		t.Fatalf("seed stored %d keys, want 1", len(kv.contents))
	}

	var got *testSessionData
	var isNew bool
	drop := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		got = sess.Get()
		isNew = sess.IsNew()
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/drop", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	drop.ServeHTTP(rr, req)
	if *got != (testSessionData{}) {
		t.Fatalf("Get after Onload drop = %#v, want zero", got)
	}
	if !isNew {
		t.Fatal("dropped session should be new")
	}
	if len(kv.contents) != 0 {
		t.Fatalf("OnloadDelete should delete KV session, got %d keys", len(kv.contents))
	}
	cleared := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == mgr.cookieSettings.Name && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("OnloadDelete should clear the session cookie")
	}
}

func TestKVManager_OnloadSavePersistsTransformation(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	seedManager, err := NewKVManager[testSessionData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedManager.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		saveTestUser(seedManager.FromContext(r.Context()), "alice")
	}))
	_, cookies := contractRequest(t, seed, nil)

	loadManager, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{
		Onload: func(data *testSessionData) (OnloadAction, error) {
			data.User = "migrated-" + data.User
			return OnloadSave, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	load := loadManager.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		data := loadManager.FromContext(r.Context()).Get()
		if got := data.User; got != "migrated-alice" {
			t.Fatalf("Onload data = %q", got)
		}
		data.User = "handler-unsaved"
	}))
	_, cookies = contractRequest(t, load, cookies)

	plain, err := NewKVManager[testSessionData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	read := plain.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := plain.FromContext(r.Context()).Get().User; got != "migrated-alice" {
			t.Fatalf("persisted data = %q", got)
		}
	}))
	contractRequest(t, read, cookies)
}

func TestKVManager_OnloadErrorDoesNotWriteOrDelete(t *testing.T) {
	for _, eager := range []bool{false, true} {
		name := "lazy"
		if eager {
			name = "eager"
		}
		t.Run(name, func(t *testing.T) {
			kv := &memoryKV{contents: make(map[string]kvItem)}
			seedManager, err := NewKVManager[testSessionData](kv, nil)
			if err != nil {
				t.Fatal(err)
			}
			seed := seedManager.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				saveTestUser(seedManager.FromContext(r.Context()), "alice")
			}))
			_, cookies := contractRequest(t, seed, nil)
			if len(kv.contents) != 1 {
				t.Fatalf("seeded entries = %d", len(kv.contents))
			}
			var key string
			var before kvItem
			for key, before = range kv.contents {
				before.data = append([]byte(nil), before.data...)
			}

			loadManager, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{
				EagerLoad:   eager,
				IdleTimeout: time.Hour,
				Onload: func(data *testSessionData) (OnloadAction, error) {
					data.User = "must-not-persist"
					return OnloadDelete, errors.New("migration unavailable")
				},
				ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
					if !strings.Contains(err.Error(), "migration unavailable") {
						t.Errorf("error = %v", err)
					}
					http.Error(w, "load failed", http.StatusServiceUnavailable)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			handlerCalled := false
			load := loadManager.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				handlerCalled = true
				_ = loadManager.FromContext(r.Context()).Get()
			}))
			recorder, _ := contractRequest(t, load, cookies)
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d", recorder.Code)
			}
			if eager && handlerCalled {
				t.Fatal("eager Onload failure ran application handler")
			}
			if !eager && !handlerCalled {
				t.Fatal("lazy Onload failure was not discovered by handler access")
			}
			after, ok := kv.contents[key]
			if !ok || !bytes.Equal(after.data, before.data) || !after.expiresAt.Equal(before.expiresAt) || len(kv.contents) != 1 {
				t.Fatalf("stored session changed after Onload error: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestKVManager_UnknownOnloadActionIsManagerError(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	seedManager, err := NewKVManager[testSessionData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedManager.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		saveTestUser(seedManager.FromContext(r.Context()), "alice")
	}))
	_, cookies := contractRequest(t, seed, nil)

	var handled error
	loadManager, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{
		EagerLoad: true,
		Onload: func(*testSessionData) (OnloadAction, error) {
			return OnloadAction(255), nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			handled = err
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	load := loadManager.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler ran after invalid Onload action")
	}))
	contractRequest(t, load, cookies)
	if handled == nil || !strings.Contains(handled.Error(), "unknown session Onload action 255") {
		t.Fatalf("handled error = %v", handled)
	}
	if len(kv.contents) != 1 {
		t.Fatalf("invalid action changed store: %d entries", len(kv.contents))
	}
}

func TestKVManager_OnloadSaveSnapshotErrorDoesNotWrite(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	seedManager, err := NewKVManager[snapshotErrorData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedManager.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := seedManager.FromContext(r.Context())
		s.Get().Value = "stored"
		s.Save()
	}))
	_, cookies := contractRequest(t, seed, nil)
	var before kvItem
	for _, before = range kv.contents {
		before.data = append([]byte(nil), before.data...)
	}

	var handled error
	loadManager, err := NewKVManager[snapshotErrorData](kv, &KVManagerOpts[snapshotErrorData]{
		EagerLoad: true,
		Onload: func(data *snapshotErrorData) (OnloadAction, error) {
			data.Value = "fail"
			return OnloadSave, nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			handled = err
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	load := loadManager.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler ran after OnloadSave snapshot error")
	}))
	contractRequest(t, load, cookies)
	if handled == nil || !strings.Contains(handled.Error(), "snapshot failed") {
		t.Fatalf("handled error = %v", handled)
	}
	if len(kv.contents) != 1 {
		t.Fatalf("entries = %d", len(kv.contents))
	}
	for _, after := range kv.contents {
		if !bytes.Equal(after.data, before.data) || !after.expiresAt.Equal(before.expiresAt) {
			t.Fatal("OnloadSave snapshot error changed stored session")
		}
	}
}

func TestKVManager_OnloadRunsForNullPayload(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	m, err := NewKVManager[testSessionData](kv, &KVManagerOpts[testSessionData]{
		EagerLoad: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "null-data-session"
	blob, err := m.codec.Encode(sessionMeta{CreatedAt: time.Now()}, []byte("null"))
	if err != nil {
		t.Fatal(err)
	}
	if err := kv.Set(context.Background(), managerHashSessionID(sessionID), time.Now().Add(time.Hour), blob); err != nil {
		t.Fatal(err)
	}
	called := false
	m.opts.Onload = func(data *testSessionData) (OnloadAction, error) {
		called = true
		data.User = "from-null"
		return OnloadUse, nil
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: m.cookieSettings.Name, Value: sessionID})
	m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		data := m.FromContext(r.Context()).Get()
		if data == nil || data.User != "from-null" {
			t.Fatalf("Get() = %#v", data)
		}
	})).ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("Onload did not run for a found null payload")
	}
}

func TestKVManagerMetadataWriteDoesNotCaptureUnsavedData(t *testing.T) {
	for _, selected := range []Codec{nil, GobCodec{}} {
		name := "json"
		if selected != nil {
			name = "gob"
		}
		t.Run(name, func(t *testing.T) {
			m, err := NewKVManager[testSessionData](NewMemoryKV(), &KVManagerOpts[testSessionData]{Codec: selected})
			if err != nil {
				t.Fatal(err)
			}
			seed := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				s := m.FromContext(r.Context())
				s.Get().User = "stored"
				s.Save()
			}))
			_, cookies := contractRequest(t, seed, nil)

			add := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				s := m.FromContext(r.Context())
				s.Get().User = "unsaved"
				s.AddFlash(Flash{Message: "notice"})
			}))
			_, cookies = contractRequest(t, add, cookies)

			read := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				s := m.FromContext(r.Context())
				if got := s.Get().User; got != "stored" {
					t.Fatalf("persisted user = %q", got)
				}
				if flashes := s.TakeFlashes(); len(flashes) != 1 || flashes[0].Message != "notice" {
					t.Fatalf("flashes = %#v", flashes)
				}
			}))
			contractRequest(t, read, cookies)
		})
	}
}

func TestKVManagerMetadataWriteDoesNotCaptureNestedMutation(t *testing.T) {
	type nestedData struct {
		Labels map[string]string
	}
	for _, selected := range []Codec{nil, GobCodec{}} {
		name := "json"
		if selected != nil {
			name = "gob"
		}
		t.Run(name, func(t *testing.T) {
			m, err := NewKVManager[nestedData](NewMemoryKV(), &KVManagerOpts[nestedData]{Codec: selected})
			if err != nil {
				t.Fatal(err)
			}
			seed := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				s := m.FromContext(r.Context())
				s.Get().Labels = map[string]string{"role": "reader"}
				s.Save()
			}))
			_, cookies := contractRequest(t, seed, nil)

			mutate := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				s := m.FromContext(r.Context())
				s.Get().Labels["role"] = "admin"
				s.AddFlash(Flash{Message: "notice"})
			}))
			_, cookies = contractRequest(t, mutate, cookies)

			read := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				if got := m.FromContext(r.Context()).Get().Labels["role"]; got != "reader" {
					t.Fatalf("persisted nested mutation = %q", got)
				}
			}))
			contractRequest(t, read, cookies)
		})
	}
}

func TestKVManagerFreshMetadataWriteUsesZeroPayload(t *testing.T) {
	for _, selected := range []Codec{nil, GobCodec{}} {
		name := "json"
		if selected != nil {
			name = "gob"
		}
		t.Run(name, func(t *testing.T) {
			m, err := NewKVManager[testSessionData](NewMemoryKV(), &KVManagerOpts[testSessionData]{Codec: selected})
			if err != nil {
				t.Fatal(err)
			}
			write := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				s := m.FromContext(r.Context())
				s.Get().User = "unsaved"
				s.AddFlash(Flash{Message: "notice"})
			}))
			_, cookies := contractRequest(t, write, nil)

			read := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				s := m.FromContext(r.Context())
				if got := s.Get().User; got != "" {
					t.Fatalf("fresh metadata write persisted user %q", got)
				}
				if flashes := s.TakeFlashes(); len(flashes) != 1 || flashes[0].Message != "notice" {
					t.Fatalf("flashes = %#v", flashes)
				}
			}))
			contractRequest(t, read, cookies)
		})
	}
}

func TestKVManagerSnapshotErrorsAreDeferredAndRecoverable(t *testing.T) {
	t.Run("failed Save has no persistence effects", func(t *testing.T) {
		kv := &memoryKV{contents: make(map[string]kvItem)}
		var handled error
		m, err := NewKVManager[snapshotErrorData](kv, &KVManagerOpts[snapshotErrorData]{
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				handled = err
				w.WriteHeader(http.StatusInternalServerError)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		write := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			s := m.FromContext(r.Context())
			s.Get().Value = "fail"
			s.Save()
		}))
		recorder, _ := contractRequest(t, write, nil)
		if recorder.Code != http.StatusInternalServerError || handled == nil || len(kv.contents) != 0 {
			t.Fatalf("status=%d error=%v entries=%d", recorder.Code, handled, len(kv.contents))
		}
		if len(recorder.Result().Cookies()) != 0 {
			t.Fatalf("failed snapshot emitted cookies: %#v", recorder.Result().Cookies())
		}
	})

	t.Run("later successful Save clears error", func(t *testing.T) {
		m, err := NewKVManager[snapshotErrorData](NewMemoryKV(), nil)
		if err != nil {
			t.Fatal(err)
		}
		write := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			s := m.FromContext(r.Context())
			s.Get().Value = "fail"
			s.Save()
			s.Get().Value = "recovered"
			s.Save()
		}))
		_, cookies := contractRequest(t, write, nil)
		read := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if got := m.FromContext(r.Context()).Get().Value; got != "recovered" {
				t.Fatalf("persisted value = %q", got)
			}
		}))
		contractRequest(t, read, cookies)
	})
}

func TestKVManagerFailedResetDoesNotDeleteOldSession(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	m, err := NewKVManager[snapshotErrorData](kv, &KVManagerOpts[snapshotErrorData]{
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusInternalServerError)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	seed := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		s.Get().Value = "stored"
		s.Save()
	}))
	_, cookies := contractRequest(t, seed, nil)
	if len(kv.contents) != 1 {
		t.Fatalf("seeded entries = %d", len(kv.contents))
	}

	reset := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		s.Get().Value = "fail"
		s.Reset()
	}))
	recorder, _ := contractRequest(t, reset, cookies)
	if recorder.Code != http.StatusInternalServerError || len(kv.contents) != 1 {
		t.Fatalf("status=%d entries=%d", recorder.Code, len(kv.contents))
	}
	read := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := m.FromContext(r.Context()).Get().Value; got != "stored" {
			t.Fatalf("old session data = %q", got)
		}
	}))
	contractRequest(t, read, cookies)
}

func TestKVManagerDeleteOverridesPendingSnapshotError(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	m, err := NewKVManager[snapshotErrorData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		s.Get().Value = "stored"
		s.Save()
	}))
	_, cookies := contractRequest(t, seed, nil)

	remove := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		s.Get().Value = "fail"
		s.Save()
		s.Delete()
	}))
	contractRequest(t, remove, cookies)
	if len(kv.contents) != 0 {
		t.Fatalf("Delete left %d entries after failed Save", len(kv.contents))
	}
}
