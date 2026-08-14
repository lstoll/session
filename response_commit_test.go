package session

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionMutationAfterResponseCommitPanics(t *testing.T) {
	type operation struct {
		name    string
		prepare func(*Session[testSessionData])
		mutate  func(*Session[testSessionData], http.ResponseWriter, *http.Request)
	}
	operations := []operation{
		{name: "Set", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) {
			s.Set(testSessionData{Bootstrap: "after"})
		}},
		{name: "Delete", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) { s.Delete() }},
		{name: "Reset", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) { s.Reset() }},
		{name: "FlashMessage", prepare: func(s *Session[testSessionData]) { s.SetFlashMessage("notice") }, mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) {
			s.FlashMessage()
		}},
		{name: "SetFlashError", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) { s.SetFlashError("error") }},
		{name: "SetFlashMessage", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) { s.SetFlashMessage("notice") }},
		{name: "InitiateDBSCRegistration", mutate: func(s *Session[testSessionData], w http.ResponseWriter, r *http.Request) {
			s.InitiateDBSCRegistration(w, r)
		}},
	}

	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			mgr, err := NewKVManager[testSessionData](NewMemoryKV(), &KVManagerOpts[testSessionData]{
				IdleTimeout:          time.Hour,
				DBSCRefreshInterval:  time.Minute,
				DBSCRegistrationPath: "/register",
				DBSCOrigin:           "https://example.com",
			})
			if err != nil {
				t.Fatal(err)
			}

			var panicValue any
			handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() { panicValue = recover() }()
				sess := mgr.FromContext(r.Context())
				sess.Set(testSessionData{Bootstrap: "before"})
				if op.prepare != nil {
					op.prepare(sess)
				}
				w.WriteHeader(http.StatusOK)
				op.mutate(sess, w, r)
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://example.com/", nil))

			want := fmt.Sprintf("session: %s called after response committed", op.name)
			if panicValue != want {
				t.Fatalf("panic = %#v, want %q", panicValue, want)
			}
		})
	}
}

func TestSessionReadsAfterResponseCommit(t *testing.T) {
	mgr, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		sess.Set(testSessionData{Bootstrap: "value"})
		w.WriteHeader(http.StatusOK)

		if got := sess.Get().Bootstrap; got != "value" {
			t.Fatalf("Get after commit = %q", got)
		}
		if sess.HasFlash() || sess.FlashIsError() || sess.FlashMessage() != "" {
			t.Fatal("empty flash reads after commit returned data")
		}
		_ = sess.IsNew()
		_ = sess.IsDeviceBound()
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
}
