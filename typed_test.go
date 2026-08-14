package session

import (
	"testing"
	"time"
)

type testSessionData struct {
	User      string
	Value     string
	Bootstrap string
	Number    int
}

func TestSessionDeleteThenSetStartsFreshSession(t *testing.T) {
	sess := &Session[testSessionData]{
		sessdata: persistedSession[testSessionData]{CreatedAt: time.Now().Add(-time.Hour)},
	}

	sess.Delete()
	sess.Set(testSessionData{User: "alice"})

	if sess.state != sessionDirty || !sess.rotate {
		t.Fatalf("state = %v, rotate = %v; want dirty, true", sess.state, sess.rotate)
	}
	if sess.sessdata.CreatedAt.IsZero() {
		t.Fatal("Set after Delete left CreatedAt unset")
	}
}

func TestFlashMessageClearsFlashState(t *testing.T) {
	sess := &Session[testSessionData]{}
	sess.SetFlashError("try again")
	if got := sess.FlashMessage(); got != "try again" {
		t.Fatalf("FlashMessage = %q, want try again", got)
	}
	if sess.HasFlash() {
		t.Fatal("HasFlash remained true after consuming message")
	}
}

func setTestUser(s *Session[testSessionData], value string) {
	data := s.Get()
	data.User = value
	s.Set(data)
}

func TestSessionTypedData(t *testing.T) {
	mgr := &Manager[testSessionData]{}
	sess := &Session[testSessionData]{
		mgr:    mgr,
		loaded: true,
		sessdata: persistedSession[testSessionData]{
			Data:      testSessionData{User: "alice"},
			CreatedAt: time.Now(),
		},
	}

	if got := sess.Get().User; got != "alice" {
		t.Fatalf("Get().User = %q, want alice", got)
	}

	data := sess.Get()
	data.User = "bob"
	data.Number++
	sess.Set(data)
	if got := sess.Get(); got.User != "bob" || got.Number != 1 {
		t.Fatalf("Set result = %#v", got)
	}
	if sess.state != sessionDirty {
		t.Fatal("Set did not mark session for saving")
	}

	sess.Set(testSessionData{Value: "replacement"})
	if got := sess.Get(); got != (testSessionData{Value: "replacement"}) {
		t.Fatalf("replacement result = %#v", got)
	}
}
