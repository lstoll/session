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

func TestSessionFlashQueue(t *testing.T) {
	sess := &Session[testSessionData]{loaded: true}
	want := []Flash{
		{Level: FlashLevelError, Message: "try again"},
		{Level: FlashLevel("success"), Message: ""},
	}
	for _, flash := range want {
		sess.AddFlash(flash)
	}

	got := sess.TakeFlashes()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("TakeFlashes() = %#v, want %#v", got, want)
	}
	if remaining := sess.TakeFlashes(); remaining != nil {
		t.Fatalf("second TakeFlashes() = %#v, want nil", remaining)
	}
	if sess.state != sessionDirty {
		t.Fatalf("state = %v, want dirty", sess.state)
	}
}

func TestTakeFlashesOnEmptySessionDoesNotMarkDirty(t *testing.T) {
	sess := &Session[testSessionData]{loaded: true}
	if got := sess.TakeFlashes(); got != nil {
		t.Fatalf("TakeFlashes() = %#v, want nil", got)
	}
	if sess.state != sessionClean {
		t.Fatalf("state = %v, want clean", sess.state)
	}
}

func TestAddFlashAfterDeleteStartsFreshSession(t *testing.T) {
	sess := &Session[testSessionData]{
		loaded:   true,
		sessdata: persistedSession[testSessionData]{CreatedAt: time.Now().Add(-time.Hour)},
	}
	sess.Delete()
	sess.AddFlash(Flash{Level: FlashLevelInfo, Message: "welcome"})

	if sess.state != sessionDirty || !sess.rotate {
		t.Fatalf("state = %v, rotate = %v; want dirty, true", sess.state, sess.rotate)
	}
	if sess.sessdata.CreatedAt.IsZero() {
		t.Fatal("AddFlash after Delete left CreatedAt unset")
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
