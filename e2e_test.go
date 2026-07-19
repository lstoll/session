package session

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func TestE2E(t *testing.T) {
	aead := newTestAEAD(t)

	t.Run("KV Manager", func(t *testing.T) {
		mgr, err := NewKVManager[testSessionData](&memoryKV{contents: make(map[string]kvItem)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		runE2ETest(t, mgr, true)
	})

	t.Run("KV Manager with session ID MAC", func(t *testing.T) {
		mgr, err := NewKVManager[testSessionData](&memoryKV{contents: make(map[string]kvItem)}, &KVManagerOpts[testSessionData]{
			SessionIDMAC: newTestMAC(t)})

		if err != nil {
			t.Fatal(err)
		}
		runE2ETest(t, mgr, true)
	})

	t.Run("Cookie Manager", func(t *testing.T) {
		mgr, err := NewCookieManager[testSessionData](aead, nil)
		if err != nil {
			t.Fatal(err)
		}
		runE2ETest(t, mgr, false)
	})
}

func runE2ETest(t testing.TB, mgr *Manager[testSessionData], testReset bool) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /set", func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("value")
		if value == "" {
			t.Logf("query with no value")
			http.Error(w, "query with no value", http.StatusInternalServerError)
			return
		}

		t.Logf("Setting session value=%s", value)
		sess := mgr.FromContext(r.Context())
		data := sess.Get()
		data.Value = value
		sess.Set(data)
	})

	mux.HandleFunc("GET /get", func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		t.Logf("Session data in context: %+v", sess.sessdata.Data)

		value := sess.Get().Value
		if value == "" {
			http.Error(w, "value not in session", http.StatusNotFound)
			return
		}

		_, _ = w.Write([]byte(value))
	})

	if testReset {
		mux.HandleFunc("GET /reset", func(w http.ResponseWriter, r *http.Request) {
			mgr.FromContext(r.Context()).Reset()
		})
	}

	mux.HandleFunc("GET /clear", func(w http.ResponseWriter, r *http.Request) {
		mgr.FromContext(r.Context()).Delete()
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
		doReq(t, client, svr.URL+fmt.Sprintf("/set?value=value%d", i), http.StatusOK)
		resp := doReq(t, client, svr.URL+"/get", http.StatusOK)
		if resp != fmt.Sprintf("value%d", i) {
			t.Fatalf("wanted returned value value%d, got: %s", i, resp)
		}
	}

	if testReset {
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
		doReq(t, client, svr.URL+"/get", http.StatusOK)

		// this should fail, as the old session should no longer be accessible under
		// this ID.
		doReq(t, oldClient, svr.URL+"/get", http.StatusNotFound)

		// clear it, and make sure it doesn't work
		for _, c := range []*http.Client{client, oldClient} {
			doReq(t, c, svr.URL+"/clear", http.StatusOK)
			doReq(t, c, svr.URL+"/get", http.StatusNotFound)
		}
	}
}

func doReq(t testing.TB, client *http.Client, url string, wantStatus int) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	// Log cookies being sent
	t.Logf("Request cookies for %s: %v", url, req.Cookies())

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("error in request to %s: %v", url, err)
	}
	bb, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	// Log response cookies
	t.Logf("Response cookies from %s: %v", url, resp.Cookies())

	if resp.StatusCode != wantStatus {
		t.Logf("body: %s", string(bb))
		t.Fatalf("non-%d response status: %d", wantStatus, resp.StatusCode)
	}
	assertNoDuplicateCookies(t, resp.Cookies())
	return string(bb)
}

func assertNoDuplicateCookies(t testing.TB, cookies []*http.Cookie) {
	t.Helper()

	seen := make(map[string]struct{})
	for _, cookie := range cookies {
		if _, exists := seen[cookie.Name]; exists {
			t.Errorf("cookie %s has multiple set's", cookie.Name)
		}
		seen[cookie.Name] = struct{}{}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("error: %v", err))
	}
	return v
}

func newTestAEAD(t *testing.T) tink.AEAD {
	t.Helper()
	handle, err := keyset.NewHandle(aead.XAES256GCM192BitNonceKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	prim, err := aead.New(handle)
	if err != nil {
		t.Fatal(err)
	}
	return prim
}
