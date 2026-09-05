package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"lds.li/session/internal/testsession"
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

func TestManagerContext_testSessionFallback(t *testing.T) {
	mgr, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, state := testsession.WithContext(context.Background(), mgr, testsession.Initial[testSessionData]{
		Data: testSessionData{Number: 1},
	})
	sess := mgr.FromContext(ctx)
	if got := sess.Get().Number; got != 1 {
		t.Fatalf("got %v", got)
	}
	*sess.Get() = testSessionData{Number: 2}
	sess.Save()
	if snapshot := state.Snapshot(); !snapshot.Saved || snapshot.Data.Number != 2 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestManagerWrapPassesThroughTestSession(t *testing.T) {
	mgr, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx, state := testsession.WithContext(req.Context(), mgr, testsession.Initial[testSessionData]{
		Data: testSessionData{User: "fixture"},
	})
	req = req.WithContext(ctx)
	var got string
	mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = mgr.FromContext(r.Context()).Get().User
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), req)
	if got != "fixture" {
		t.Fatalf("wrapped fixture data = %q", got)
	}
	if state.Snapshot().Saved {
		t.Fatal("pass-through should not persist fixture")
	}
}
