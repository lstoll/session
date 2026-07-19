package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagerContext(t *testing.T) {
	kv := NewMemoryKV()
	mgr, err := NewKVManager[testSessionData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mgr.FromContext(r.Context()) == nil {
			t.Fatal("manager did not find its session")
		}
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("got %v", rr.Code)
	}
}

func TestManagerContext_wrongManagerReturnsFalse(t *testing.T) {
	kv := NewMemoryKV()
	mgr1, err := NewKVManager[testSessionData](kv, nil)
	if err != nil {
		t.Fatal(err)
	}
	mgr2, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
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
	mgr, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := mgr.TestContext(context.Background(), testSessionData{Number: 1})
	sess := mgr.FromContext(ctx)
	if sess.Get().Number != 1 {
		t.Fatalf("got %v", sess.Get().Number)
	}
}
