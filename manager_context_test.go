package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func resetManagerRegistryForTest(t *testing.T) {
	t.Helper()
	managerRegistryMu.Lock()
	registeredManagers = nil
	managerRegistryMu.Unlock()
}

func TestManagerContext_singletonFromContext(t *testing.T) {
	resetManagerRegistryForTest(t)

	kv := NewMemoryKV()
	mgr, err := NewKVManager(kv, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := FromContext(r.Context())
		if sess != mgr.FromContext(r.Context()) {
			t.Fatal("package and Manager FromContext disagree")
		}
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %v", rr.Code)
	}
}

func TestManagerContext_multipleManagersPanic(t *testing.T) {
	resetManagerRegistryForTest(t)

	kv := NewMemoryKV()
	mgr1, err := NewKVManager(kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	mgr2, err := NewKVManager(NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}

	handler := mgr1.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic from package FromContext with multiple Managers")
			}
		}()
		FromContext(r.Context())
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	// mgr2 can still read only its own sessions.
	handler2 := mgr2.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgr2.FromContext(r.Context()).Set("k", "v")
		w.WriteHeader(http.StatusOK)
	}))
	rr2 := httptest.NewRecorder()
	handler2.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("mgr2 handler: got %v", rr2.Code)
	}
}

func TestManagerContext_wrongManagerReturnsFalse(t *testing.T) {
	resetManagerRegistryForTest(t)

	kv := NewMemoryKV()
	mgr1, err := NewKVManager(kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	mgr2, err := NewKVManager(NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}

	var ctx context.Context
	handler := mgr1.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx = r.Context()
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("mgr2 should not see session installed by mgr1")
			}
		}()
		mgr2.FromContext(ctx)
	}()
	mgr1.FromContext(ctx)
}

func TestTestContext_fromContextFallback(t *testing.T) {
	resetManagerRegistryForTest(t)

	ctx, _ := TestContext(context.Background(), &Session{
		sessdata: persistedSession{
			Data: map[string]any{"x": 1},
		},
	})
	sess := FromContext(ctx)
	if sess.Get("x") != 1 {
		t.Fatalf("got %v", sess.Get("x"))
	}
}
