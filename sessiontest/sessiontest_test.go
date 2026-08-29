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
		sessiontest.WithFlash(session.Flash{Level: "success", Message: "welcome back"}),
	)

	if change.IsNew() {
		t.Fatal("attached session should represent an existing session by default")
	}
	if got := change.Flashes(); len(got) != 2 ||
		got[0] != (session.Flash{Level: session.FlashLevelError, Message: "sign in again"}) ||
		got[1] != (session.Flash{Level: "success", Message: "welcome back"}) {
		t.Fatalf("initial flashes = %#v", got)
	}

	handler := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		sess := manager.FromContext(request.Context())
		if got := sess.TakeFlashes(); len(got) != 2 || got[0].Message != "sign in again" || got[1].Message != "welcome back" {
			t.Fatalf("TakeFlashes() = %#v", got)
		}
		sess.Get().UserID = "bob"
		sess.Save()
	})
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if !change.Saved() || change.Deleted() || change.Reset() {
		t.Fatalf("change = saved %v, deleted %v, reset %v", change.Saved(), change.Deleted(), change.Reset())
	}
	if got := change.Data().UserID; got != "bob" {
		t.Fatalf("Data().UserID = %q", got)
	}
	if got := change.Flashes(); len(got) != 0 {
		t.Fatalf("consumed flashes remain: %#v", got)
	}
}

func TestWithSessionPassesThroughManagerWrap(t *testing.T) {
	manager := newManager(t)
	request, change := sessiontest.WithSession(
		t,
		httptest.NewRequest(http.MethodGet, "/", nil),
		manager,
		sessionData{UserID: "fixture"},
	)
	manager.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		sess := manager.FromContext(request.Context())
		if got := sess.Get().UserID; got != "fixture" {
			t.Fatalf("fixture user = %q", got)
		}
		sess.Get().UserID = "changed"
		sess.Save()
	})).ServeHTTP(httptest.NewRecorder(), request)
	if !change.Saved() || change.Data().UserID != "changed" {
		t.Fatalf("change = saved %v data %#v", change.Saved(), change.Data())
	}
}

func TestWithSessionMetadataOnlyChangeIsNotSavedData(t *testing.T) {
	manager := newManager(t)
	request, change := sessiontest.WithSession(
		t,
		httptest.NewRequest(http.MethodGet, "/", nil),
		manager,
		sessionData{},
	)
	manager.FromContext(request.Context()).AddFlash(session.Flash{Message: "notice"})
	if change.Saved() {
		t.Fatal("metadata-only change reported application data as saved")
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
		flashes := change.Flashes()
		if !change.IsNew() || len(flashes) != 1 || flashes[0].Level != session.FlashLevelInfo {
			t.Fatal("new informational-flash session was not attached")
		}
		manager.FromContext(request.Context()).Reset()
		if !change.Saved() || !change.Reset() {
			t.Fatalf("change = saved %v, reset %v", change.Saved(), change.Reset())
		}
	})
}
