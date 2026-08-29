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
		{name: "Save", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) {
			*s.Get() = testSessionData{Bootstrap: "after"}
			s.Save()
		}},
		{name: "Delete", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) { s.Delete() }},
		{name: "Reset", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) { s.Reset() }},
		{name: "TakeFlashes", prepare: func(s *Session[testSessionData]) {
			s.AddFlash(Flash{Level: FlashLevelInfo, Message: "notice"})
		}, mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) {
			s.TakeFlashes()
		}},
		{name: "AddFlash", mutate: func(s *Session[testSessionData], _ http.ResponseWriter, _ *http.Request) {
			s.AddFlash(Flash{Level: FlashLevelError, Message: "error"})
		}},
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
				*sess.Get() = testSessionData{Bootstrap: "before"}
				sess.Save()
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
		*sess.Get() = testSessionData{Bootstrap: "value"}
		sess.Save()
		w.WriteHeader(http.StatusOK)

		if got := sess.Get().Bootstrap; got != "value" {
			t.Fatalf("Get after commit = %q", got)
		}
		if flashes := sess.TakeFlashes(); flashes != nil {
			t.Fatalf("TakeFlashes after commit = %#v, want nil", flashes)
		}
		_ = sess.IsNew()
		_ = sess.IsDeviceBound()
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://example.com/", nil))
}
