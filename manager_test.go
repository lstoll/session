package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type touchRecordingStore[T any] struct {
	expiresAt time.Time
	data      []byte
}

//nolint:unused // Implements sessionStore; golangci-lint does not resolve the generic interface implementation.
func (*touchRecordingStore[T]) load(*http.Request) ([]byte, bool, error) {
	return nil, false, nil
}

//nolint:unused // Implements sessionStore; golangci-lint does not resolve the generic interface implementation.
func (*touchRecordingStore[T]) save(http.ResponseWriter, *http.Request, time.Time, []byte) error {
	return nil
}

//nolint:unused // Implements sessionStore; golangci-lint does not resolve the generic interface implementation.
func (*touchRecordingStore[T]) delete(*http.Request) error { return nil }

//nolint:unused // Implements sessionStore; golangci-lint does not resolve the generic interface implementation.
func (s *touchRecordingStore[T]) touch(_ http.ResponseWriter, _ *http.Request, expiresAt time.Time, data []byte) error {
	s.expiresAt = expiresAt
	s.data = data
	return nil
}

func TestItem_InvalidAt(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		item        sessionMeta
		maxLifetime *time.Duration
		idleTimeout *time.Duration
		want        time.Time
	}{
		{
			name:        "Max lifetime only",
			item:        sessionMeta{CreatedAt: now},
			maxLifetime: ptr(2 * time.Hour),
			want:        now.Add(2 * time.Hour),
		},
		{
			name:        "Idle timeout only (CreatedAt)",
			item:        sessionMeta{CreatedAt: now},
			idleTimeout: ptr(1 * time.Hour),
			want:        now.Add(1 * time.Hour),
		},
		{
			name:        "Idle timeout only (UpdatedAt)",
			item:        sessionMeta{CreatedAt: now, UpdatedAt: now.Add(30 * time.Minute)},
			idleTimeout: ptr(1 * time.Hour),
			want:        now.Add(30 * time.Minute).Add(1 * time.Hour),
		},
		{
			name:        "Both timeouts, MaxLifetime earlier",
			item:        sessionMeta{CreatedAt: now, UpdatedAt: now.Add(30 * time.Minute)},
			maxLifetime: ptr(1 * time.Hour),
			idleTimeout: ptr(2 * time.Hour),
			want:        now.Add(1 * time.Hour),
		},
		{
			name:        "Both timeouts, IdleTimeout earlier (CreatedAt)",
			item:        sessionMeta{CreatedAt: now},
			maxLifetime: ptr(2 * time.Hour),
			idleTimeout: ptr(1 * time.Hour),
			want:        now.Add(1 * time.Hour),
		},
		{
			name:        "Both timeouts, IdleTimeout earlier (UpdatedAt)",
			item:        sessionMeta{CreatedAt: now, UpdatedAt: now.Add(1 * time.Hour)},
			maxLifetime: ptr(2 * time.Hour),
			idleTimeout: ptr(1 * time.Hour),
			want:        now.Add(1 * time.Hour).Add(1 * time.Hour), // 2 hours from original CreatedAt
		},
		{
			name:        "UpdatedAt is nil, Idle Timeout",
			item:        sessionMeta{CreatedAt: now},
			idleTimeout: ptr(1 * time.Hour),
			want:        now.Add(1 * time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &Manager[struct{}]{}
			if tt.maxLifetime != nil {
				mgr.opts.MaxLifetime = *tt.maxLifetime
			}
			if tt.idleTimeout != nil {
				mgr.opts.IdleTimeout = *tt.idleTimeout
			}

			got := mgr.calculateExpiry(tt.item)
			if !got.Equal(tt.want) {
				t.Errorf("InvalidAt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManagerRejectsPointerAndInterfaceDataTypes(t *testing.T) {
	if _, err := NewKVManager[*testSessionData](NewMemoryKV(), nil); err == nil {
		t.Fatal("pointer session data type accepted")
	}
	if _, err := NewKVManager[any](NewMemoryKV(), nil); err == nil {
		t.Fatal("interface session data type accepted")
	}
	if _, err := NewKVManager[string](NewMemoryKV(), nil); err != nil {
		t.Fatalf("string session data type rejected: %v", err)
	}
	mapManager, err := NewKVManager[map[string]string](NewMemoryKV(), nil)
	if err != nil {
		t.Fatalf("map session data type rejected: %v", err)
	}
	var got *map[string]string
	mapManager.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = mapManager.FromContext(r.Context()).Get()
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got == nil || *got != nil {
		t.Fatalf("zero map data = %#v; want non-nil pointer to nil map", got)
	}
}

func TestTouchSessionAdvancesIdleExpiryAndPersistsUpdatedAt(t *testing.T) {
	const idleTimeout = time.Hour
	codec := &gobCodec{}
	store := &touchRecordingStore[string]{}
	mgr := &Manager[string]{
		store: store,
		codec: codec,
		opts:  managerOpts[string]{IdleTimeout: idleTimeout},
	}

	originalData := "stored"
	originalMeta := sessionMeta{
		CreatedAt: time.Now().Add(-2 * time.Hour),
		UpdatedAt: time.Now().Add(-30 * time.Minute),
	}
	payload, err := codec.MarshalPayload(&originalData)
	if err != nil {
		t.Fatal(err)
	}
	sctx := &Session[string]{
		meta:    originalMeta,
		payload: payload,
		working: ptr("transformed"),
	}
	// Simulate an Onload transformation. A clean-session touch must not persist it.

	before := time.Now()
	if err := mgr.touchSession(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		sctx,
	); err != nil {
		t.Fatal(err)
	}
	after := time.Now()

	meta, payload, err := codec.Decode(store.data)
	if err != nil {
		t.Fatal(err)
	}
	var persistedData string
	if err := codec.UnmarshalPayload(payload, &persistedData); err != nil {
		t.Fatal(err)
	}
	if persistedData != originalData {
		t.Fatalf("persisted data = %q, want original %q", persistedData, originalData)
	}
	if meta.UpdatedAt.Before(before) || meta.UpdatedAt.After(after) {
		t.Fatalf("persisted UpdatedAt = %v, want between %v and %v", meta.UpdatedAt, before, after)
	}
	if !sctx.meta.UpdatedAt.Equal(meta.UpdatedAt) {
		t.Fatalf("in-memory UpdatedAt = %v, persisted %v", sctx.meta.UpdatedAt, meta.UpdatedAt)
	}
	wantExpiry := meta.UpdatedAt.Add(idleTimeout)
	if !store.expiresAt.Equal(wantExpiry) {
		t.Fatalf("expiry = %v, want %v", store.expiresAt, wantExpiry)
	}
	if !store.expiresAt.After(originalMeta.UpdatedAt.Add(idleTimeout)) {
		t.Fatalf("expiry did not advance: got %v, original %v", store.expiresAt, originalMeta.UpdatedAt.Add(idleTimeout))
	}
}

func TestManagerConstructorValidation(t *testing.T) {
	tests := []struct {
		name        string
		maxLifetime time.Duration
		idleTimeout time.Duration
		cookieOpts  SessionCookieOpts
		wantErr     string
	}{
		{
			name:        "negative max lifetime",
			maxLifetime: -time.Second,
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "session", Path: "/"},
			wantErr:     "MaxLifetime must not be negative",
		},
		{
			name:        "negative idle timeout",
			maxLifetime: time.Hour,
			idleTimeout: -time.Second,
			cookieOpts:  SessionCookieOpts{Name: "session", Path: "/"},
			wantErr:     "IdleTimeout must not be negative",
		},
		{
			name:        "empty cookie name",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Path: "/"},
			wantErr:     "invalid Cookie.Name",
		},
		{
			name:        "invalid cookie name",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "bad name", Path: "/"},
			wantErr:     "invalid Cookie.Name",
		},
		{
			name:        "empty cookie path",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "session"},
			wantErr:     "absolute path",
		},
		{
			name:        "relative cookie path",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "session", Path: "app"},
			wantErr:     "absolute path",
		},
		{
			name:        "invalid cookie path byte",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "session", Path: "/app;admin"},
			wantErr:     "invalid byte",
		},
		{
			name:        "insecure host cookie",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "__Host-session", Path: "/", Insecure: true},
			wantErr:     "__Host- require Secure",
		},
		{
			name:        "scoped host cookie",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "__Host-session", Path: "/app"},
			wantErr:     "__Host- require Path /",
		},
		{
			name:        "insecure secure-prefix cookie",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "__Secure-session", Path: "/", Insecure: true},
			wantErr:     "__Secure- require Secure",
		},
		{
			name:        "persist without max lifetime",
			idleTimeout: time.Hour,
			cookieOpts:  SessionCookieOpts{Name: "session", Path: "/", Insecure: true, Persist: true},
			wantErr:     "Persist option requires MaxLifetime",
		},
	}

	for _, managerType := range []string{"cookie", "KV"} {
		for _, tt := range tests {
			t.Run(managerType+"/"+tt.name, func(t *testing.T) {
				var err error
				switch managerType {
				case "cookie":
					_, err = NewCookieManager[string](newTestAEAD(t), &CookieManagerOpts[string]{
						MaxLifetime: tt.maxLifetime,
						IdleTimeout: tt.idleTimeout,
						CookieOpts:  &tt.cookieOpts,
					})
				case "KV":
					_, err = NewKVManager[string](NewMemoryKV(), &KVManagerOpts[string]{
						MaxLifetime: tt.maxLifetime,
						IdleTimeout: tt.idleTimeout,
						CookieOpts:  &tt.cookieOpts,
					})
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
			})
		}
	}
}

func TestManagerConstructorAcceptsValidScopedCookie(t *testing.T) {
	cookieOpts := &SessionCookieOpts{Name: "app-session", Path: "/app", Insecure: true, Persist: true}
	if _, err := NewCookieManager[string](newTestAEAD(t), &CookieManagerOpts[string]{
		MaxLifetime: 24 * time.Hour,
		CookieOpts:  cookieOpts,
	}); err != nil {
		t.Fatalf("NewCookieManager: %v", err)
	}
	if _, err := NewKVManager[string](NewMemoryKV(), &KVManagerOpts[string]{
		MaxLifetime: 24 * time.Hour,
		CookieOpts:  cookieOpts,
	}); err != nil {
		t.Fatalf("NewKVManager: %v", err)
	}
}

func TestManagerDefaultLifetimeIsAbsolute(t *testing.T) {
	cookieMgr, err := NewCookieManager[string](newTestAEAD(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	kvMgr, err := NewKVManager[string](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mgr := range []*Manager[string]{cookieMgr, kvMgr} {
		if mgr.opts.MaxLifetime != DefaultMaxLifetime || mgr.opts.IdleTimeout != 0 {
			t.Fatalf("default lifetime = max %v idle %v, want max %v idle 0", mgr.opts.MaxLifetime, mgr.opts.IdleTimeout, DefaultMaxLifetime)
		}
	}

	idleOnly, err := NewKVManager[string](NewMemoryKV(), &KVManagerOpts[string]{IdleTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if idleOnly.opts.MaxLifetime != 0 || idleOnly.opts.IdleTimeout != time.Hour {
		t.Fatalf("explicit idle-only = max %v idle %v", idleOnly.opts.MaxLifetime, idleOnly.opts.IdleTimeout)
	}
}

func TestKVManagerRequiresStore(t *testing.T) {
	if _, err := NewKVManager[string](nil, nil); err == nil {
		t.Fatal("NewKVManager accepted a nil KV store")
	}
}

func TestManagerSetCookieValidatesCompleteSerializedSize(t *testing.T) {
	cookie := &http.Cookie{
		Name:     "custom-session-name",
		Path:     "/a/scoped/application/path",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	}
	overhead := len(cookie.String())
	cookie.Value = strings.Repeat("x", managerMaxSetCookieSize-overhead)
	if got := len(cookie.String()); got != managerMaxSetCookieSize {
		t.Fatalf("test cookie size = %d, want %d", got, managerMaxSetCookieSize)
	}

	w := httptest.NewRecorder()
	if err := managerSetCookie(w, cookie); err != nil {
		t.Fatalf("cookie at limit rejected: %v", err)
	}
	if got := w.Header().Get("Set-Cookie"); len(got) != managerMaxSetCookieSize {
		t.Fatalf("Set-Cookie size = %d, want %d", len(got), managerMaxSetCookieSize)
	}

	cookie.Value += "x"
	w = httptest.NewRecorder()
	if err := managerSetCookie(w, cookie); err == nil {
		t.Fatal("cookie over serialized size limit accepted")
	}
	if got := w.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("oversized cookie was emitted: %q", got)
	}
}

func ptr[T any](v T) *T {
	return &v
}
