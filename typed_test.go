package session

import (
	"net/http"
	"testing"
	"time"
)

type testSessionData struct {
	User      string
	Value     string
	Bootstrap string
	Number    int
}

func TestSessionResetRestartsLifetime(t *testing.T) {
	created := time.Now().Add(-2 * time.Hour)
	updated := time.Now().Add(-time.Hour)
	sess := &Session[testSessionData]{
		mgr:    &Manager[testSessionData]{codec: &jsonCodec{}},
		loaded: true,
		meta: sessionMeta{
			CreatedAt: created,
			UpdatedAt: updated,
		},
		working: &testSessionData{User: "alice"},
	}

	before := time.Now()
	sess.Reset()
	after := time.Now()

	if !sess.rotate || !sess.dataScheduled || !sess.metaDirty || sess.deleted {
		t.Fatalf("rotate = %v, dataScheduled = %v, metaDirty = %v, deleted = %v", sess.rotate, sess.dataScheduled, sess.metaDirty, sess.deleted)
	}
	if sess.Get().User != "alice" {
		t.Fatal("Reset dropped session data")
	}
	if sess.meta.CreatedAt.Equal(created) || sess.meta.UpdatedAt.Equal(updated) {
		t.Fatal("Reset kept previous timestamps")
	}
	if sess.meta.CreatedAt.Before(before) || sess.meta.CreatedAt.After(after) {
		t.Fatalf("CreatedAt = %v, want between %v and %v", sess.meta.CreatedAt, before, after)
	}
	if !sess.meta.UpdatedAt.Equal(sess.meta.CreatedAt) {
		t.Fatalf("UpdatedAt = %v, CreatedAt = %v", sess.meta.UpdatedAt, sess.meta.CreatedAt)
	}
}

func TestSessionDeleteThenSaveStartsFreshSession(t *testing.T) {
	sess := &Session[testSessionData]{
		mgr:  &Manager[testSessionData]{codec: &jsonCodec{}},
		meta: sessionMeta{CreatedAt: time.Now().Add(-time.Hour)},
	}

	sess.Delete()
	*sess.Get() = testSessionData{User: "alice"}
	sess.Save()

	if !sess.dataScheduled || !sess.rotate || sess.deleted {
		t.Fatalf("dataScheduled = %v, rotate = %v, deleted = %v", sess.dataScheduled, sess.rotate, sess.deleted)
	}
	if sess.meta.CreatedAt.IsZero() {
		t.Fatal("Save after Delete left CreatedAt unset")
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
	if !sess.metaDirty {
		t.Fatal("flash mutations did not mark metadata dirty")
	}
}

func TestTakeFlashesOnEmptySessionDoesNotScheduleWrite(t *testing.T) {
	sess := &Session[testSessionData]{loaded: true}
	if got := sess.TakeFlashes(); got != nil {
		t.Fatalf("TakeFlashes() = %#v, want nil", got)
	}
	if sess.metaDirty || sess.dataScheduled || sess.deleted {
		t.Fatalf("empty TakeFlashes scheduled a write: metaDirty=%v dataScheduled=%v deleted=%v", sess.metaDirty, sess.dataScheduled, sess.deleted)
	}
}

func TestAddFlashAfterDeleteStartsFreshSession(t *testing.T) {
	sess := &Session[testSessionData]{
		loaded: true,
		meta:   sessionMeta{CreatedAt: time.Now().Add(-time.Hour)},
	}
	sess.Delete()
	sess.AddFlash(Flash{Level: FlashLevelInfo, Message: "welcome"})

	if !sess.metaDirty || !sess.rotate || sess.deleted {
		t.Fatalf("metaDirty = %v, rotate = %v, deleted = %v", sess.metaDirty, sess.rotate, sess.deleted)
	}
	if sess.meta.CreatedAt.IsZero() {
		t.Fatal("AddFlash after Delete left CreatedAt unset")
	}
}

func TestDBSCRegistrationAfterDeleteStartsFreshSession(t *testing.T) {
	sess := &Session[testSessionData]{
		loaded:      true,
		meta:        sessionMeta{CreatedAt: time.Now().Add(-time.Hour)},
		zeroPayload: []byte(`{}`),
	}
	sess.Delete()
	issueDBSCRegistrationChallenge(sess, time.Now())

	if sess.deleted || !sess.rotate || !sess.metaDirty {
		t.Fatalf("deleted = %v, rotate = %v, metaDirty = %v", sess.deleted, sess.rotate, sess.metaDirty)
	}
	if sess.meta.CreatedAt.IsZero() {
		t.Fatal("DBSC registration after Delete left CreatedAt unset")
	}
}

func TestSessionTypedData(t *testing.T) {
	mgr := &Manager[testSessionData]{codec: &jsonCodec{}}
	sess := &Session[testSessionData]{
		mgr:    mgr,
		loaded: true,
		meta: sessionMeta{
			CreatedAt: time.Now(),
		},
		working: &testSessionData{User: "alice"},
	}

	if got := sess.Get().User; got != "alice" {
		t.Fatalf("Get().User = %q, want alice", got)
	}

	data := sess.Get()
	data.User = "bob"
	data.Number++
	sess.Save()
	if got := sess.Get(); got.User != "bob" || got.Number != 1 {
		t.Fatalf("Save result = %#v", got)
	}
	if !sess.dataScheduled {
		t.Fatal("Save did not mark session for saving")
	}

	*sess.Get() = testSessionData{Value: "replacement"}
	sess.Save()
	if got := sess.Get(); *got != (testSessionData{Value: "replacement"}) {
		t.Fatalf("replacement result = %#v", got)
	}
}

func TestSessionSaveSnapshotsAtCallTime(t *testing.T) {
	m, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	write := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		s.Get().User = "at-save"
		s.Save()
		s.Get().User = "after-save"
	}))
	_, cookies := contractRequest(t, write, nil)

	read := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := m.FromContext(r.Context()).Get().User; got != "at-save" {
			t.Fatalf("persisted user = %q", got)
		}
	}))
	contractRequest(t, read, cookies)
}

func TestSessionResetSnapshotsAndRotates(t *testing.T) {
	m, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		s.Get().User = "before"
		s.Save()
	}))
	_, cookies := contractRequest(t, seed, nil)
	oldID := cookies[0].Value

	reset := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		s.Get().User = "at-reset"
		s.Reset()
		s.Get().User = "after-reset"
	}))
	_, cookies = contractRequest(t, reset, cookies)
	if cookies[0].Value == oldID {
		t.Fatal("Reset did not rotate the session identifier")
	}

	read := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := m.FromContext(r.Context()).Get().User; got != "at-reset" {
			t.Fatalf("persisted user = %q", got)
		}
	}))
	contractRequest(t, read, cookies)
}

func TestSessionDeleteDetachesOldPointer(t *testing.T) {
	m, err := NewKVManager[testSessionData](NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		s.Get().User = "before"
		s.Save()
	}))
	_, cookies := contractRequest(t, seed, nil)

	replace := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		s := m.FromContext(r.Context())
		old := s.Get()
		s.Delete()
		old.User = "stale"
		s.Get().User = "fresh"
		s.Save()
	}))
	_, cookies = contractRequest(t, replace, cookies)

	read := m.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := m.FromContext(r.Context()).Get().User; got != "fresh" {
			t.Fatalf("persisted user = %q", got)
		}
	}))
	contractRequest(t, read, cookies)
}
