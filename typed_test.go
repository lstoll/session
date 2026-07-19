package session

import (
	"context"
	"testing"
)

type testSessionData struct {
	User      string
	Value     string
	Bootstrap string
	Number    int
}

func setTestUser(s *Session[testSessionData], value string) {
	data := s.Get()
	data.User = value
	s.Set(data)
}

func TestSessionTypedData(t *testing.T) {
	mgr := &Manager[testSessionData]{}
	ctx, result := mgr.TestContext(context.Background(), testSessionData{User: "alice"})
	sess := mgr.FromContext(ctx)

	if got := sess.Get().User; got != "alice" {
		t.Fatalf("Get().User = %q, want alice", got)
	}

	data := sess.Get()
	data.User = "bob"
	data.Number++
	sess.Set(data)
	if got := result.Result(); got.User != "bob" || got.Number != 1 {
		t.Fatalf("Set result = %#v", got)
	}
	if !result.Saved() {
		t.Fatal("Set did not mark session for saving")
	}

	sess.Set(testSessionData{Value: "replacement"})
	if got := result.Result(); got != (testSessionData{Value: "replacement"}) {
		t.Fatalf("replacement result = %#v", got)
	}
}
