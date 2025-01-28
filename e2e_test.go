package session

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	testpb "github.com/lstoll/session/internal/proto"
)

func TestE2E(t *testing.T) {
	t.Run("KV Manager, JSON", func(t *testing.T) {
		mgr := NewMemoryManager[jsonTestSession](nil)
		assertResetMgr(t, mgr)
		runE2ETest(t, mgr)
	})
	t.Run("KV Manager, Protobuf", func(t *testing.T) {
		mgr := NewMemoryManager[testpb.Session](nil)
		assertResetMgr(t, mgr)
		runE2ETest(t, mgr)
	})

	t.Run("Cookie Manager, JSON", func(t *testing.T) {
		mgr := NewCookieManager[jsonTestSession](&aesGCMAEAD{
			encryptionKey: genAESKey(),
		}, nil)
		runE2ETest(t, mgr)
	})
	t.Run("Cookie Manager, Protobuf", func(t *testing.T) {
		mgr := NewCookieManager[testpb.Session](&aesGCMAEAD{
			encryptionKey: genAESKey(),
		}, nil)
		runE2ETest(t, mgr)
	})
}

type jsonTestSession struct {
	KV map[string]string `json:"map"`
}

func (j *jsonTestSession) GetMap() map[string]string {
	return j.KV
}

func (j *jsonTestSession) SetMap(m map[string]string) {
	j.KV = m
}

type codecAccessor interface {
	GetMap() map[string]string
	SetMap(map[string]string)
}

type tmanager[T any] interface {
	Wrap(http.Handler) http.Handler
	Get(context.Context) (T, bool)
	Save(context.Context, T)
	Delete(context.Context)
}

type resetmgr[T any] interface {
	tmanager[T]
	Reset(context.Context, T)
}

// no-op, just makes the compile-time type check fail if it's not
func assertResetMgr[PtrT codecAccessor](t testing.TB, mgr resetmgr[PtrT]) {}

func runE2ETest[PtrT codecAccessor](t testing.TB, mgr tmanager[PtrT]) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /set", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := mgr.Get(r.Context())

		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "query with no key", http.StatusInternalServerError)
			return
		}

		value := r.URL.Query().Get("value")
		if key == "" {
			t.Logf("query with no value")
			http.Error(w, "query with no value", http.StatusInternalServerError)
			return
		}

		m := sess.GetMap()
		if m == nil {
			m = make(map[string]string)
		}

		m[key] = value

		sess.SetMap(m)

		mgr.Save(r.Context(), sess)
	})

	mux.HandleFunc("GET /get", func(w http.ResponseWriter, r *http.Request) {
		sess, _ := mgr.Get(r.Context())

		key := r.URL.Query().Get("key")
		if key == "" {
			t.Fatal("query with no key")
		}

		value, ok := sess.GetMap()[key]
		if !ok {
			http.Error(w, "key not in session", http.StatusNotFound)
			return
		}

		_, _ = w.Write([]byte(value))
	})

	rmgr, isReset := mgr.(resetmgr[PtrT])
	if isReset {
		mux.HandleFunc("GET /reset", func(w http.ResponseWriter, r *http.Request) {
			sess, _ := rmgr.Get(r.Context())
			rmgr.Reset(r.Context(), sess)
		})
	}

	mux.HandleFunc("GET /clear", func(w http.ResponseWriter, r *http.Request) {
		mgr.Delete(r.Context())
	})

	svr := httptest.NewTLSServer(mgr.Wrap(mux))
	t.Cleanup(svr.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: svr.Client().Transport,
		Jar:       jar,
	}

	for i := range 5 {
		doReq(t, client, svr.URL+fmt.Sprintf("/set?key=test%d&value=value%d", i, i), http.StatusOK)
	}

	// now ensure all 5 values are there
	for i := range 5 {
		resp := doReq(t, client, svr.URL+fmt.Sprintf("/get?key=test%d", i), http.StatusOK)
		if resp != fmt.Sprintf("value%d", i) {
			t.Fatalf("wanted returned value value%d, got: %s", i, resp)
		}
	}

	if isReset {
		// duplicate the jar, so after a reset we can make sure the old
		// session still can't be loaded.
		oldJar := must(cookiejar.New(nil))
		svrURL := must(url.Parse(svr.URL))
		oldJar.SetCookies(svrURL, jar.Cookies(svrURL))
		oldClient := &http.Client{
			Transport: svr.Client().Transport,
			Jar:       oldJar,
		}

		doReq(t, client, svr.URL+"/reset", http.StatusOK)
		doReq(t, client, svr.URL+"/get?key=test1", http.StatusOK)

		// this should fail, as the old session should no longer be accessible under
		// this ID.
		doReq(t, oldClient, svr.URL+"/get?key=test1", http.StatusNotFound)

		// clear it, and make sure it doesn't work
		for _, c := range []*http.Client{client, oldClient} {
			doReq(t, c, svr.URL+"/clear", http.StatusOK)
			doReq(t, c, svr.URL+"/get?key=test1", http.StatusNotFound)
			doReq(t, c, svr.URL+"/get?key=reset1", http.StatusNotFound)
		}
	}
}

func doReq(t testing.TB, client *http.Client, url string, wantStatus int) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("error in request to %s: %v", url, err)
	}
	bb, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if resp.StatusCode != wantStatus {
		t.Logf("body: %s", string(bb))
		t.Fatalf("non-%d response status: %d", wantStatus, resp.StatusCode)
	}
	return string(bb)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("error: %v", err))
	}
	return v
}

func genAESKey() []byte {
	k := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		panic(err)
	}
	return k
}
