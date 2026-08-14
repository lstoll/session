package sessiontest_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"lds.li/session"
	"lds.li/session/sessiontest"
)

type sessionData struct {
	UserID string
}

func newManager(t testing.TB) *session.Manager[sessionData] {
	t.Helper()
	manager, err := session.NewKVManager[sessionData](session.NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestWithSessionTracksDataAndFlash(t *testing.T) {
	manager := newManager(t)
	request, change := sessiontest.WithSession(
		t,
		httptest.NewRequest(http.MethodGet, "/", nil),
		manager,
		sessionData{UserID: "alice"},
		sessiontest.WithFlashError("sign in again"),
	)

	if change.IsNew() {
		t.Fatal("attached session should represent an existing session by default")
	}
	if !change.HasFlash() || !change.FlashIsError() || change.FlashMessage() != "sign in again" {
		t.Fatalf("initial flash = %q, error %v", change.FlashMessage(), change.FlashIsError())
	}

	handler := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		sess := manager.FromContext(request.Context())
		if got := sess.FlashMessage(); got != "sign in again" {
			t.Fatalf("FlashMessage() = %q", got)
		}
		data := sess.Get()
		data.UserID = "bob"
		sess.Set(data)
	})
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if !change.Saved() || change.Deleted() || change.Reset() {
		t.Fatalf("change = saved %v, deleted %v, reset %v", change.Saved(), change.Deleted(), change.Reset())
	}
	if got := change.Data().UserID; got != "bob" {
		t.Fatalf("Data().UserID = %q", got)
	}
	if change.HasFlash() || change.FlashMessage() != "" {
		t.Fatalf("consumed flash remains: %q", change.FlashMessage())
	}
}

func TestWithSessionTracksDeleteAndReset(t *testing.T) {
	manager := newManager(t)

	t.Run("delete", func(t *testing.T) {
		request, change := sessiontest.WithSession(
			t, httptest.NewRequest(http.MethodGet, "/", nil), manager, sessionData{UserID: "alice"},
		)
		manager.FromContext(request.Context()).Delete()
		if !change.Deleted() || !change.IsNew() {
			t.Fatalf("change = deleted %v, new %v", change.Deleted(), change.IsNew())
		}
	})

	t.Run("reset", func(t *testing.T) {
		request, change := sessiontest.WithSession(
			t,
			httptest.NewRequest(http.MethodGet, "/", nil),
			manager,
			sessionData{},
			sessiontest.AsNewSession(),
			sessiontest.WithFlashMessage("welcome"),
		)
		if !change.IsNew() || !change.HasFlash() || change.FlashIsError() {
			t.Fatal("new informational-flash session was not attached")
		}
		manager.FromContext(request.Context()).Reset()
		if !change.Saved() || !change.Reset() {
			t.Fatalf("change = saved %v, reset %v", change.Saved(), change.Reset())
		}
	})
}
