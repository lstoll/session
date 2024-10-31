package session

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSessionStore(t *testing.T) {
	for name, store := range map[string]Store{
		"memory-kv": NewMemoryStore(),
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()

			setHandler := func(w http.ResponseWriter, r *http.Request) {
				sess := map[string]string{}

				loaded, err := store.Get(r, &sess)
				t.Logf("GET /set: loaded %t err %v", loaded, err)
				if err != nil {
					http.Error(w, "loading store failed", http.StatusInternalServerError)
					return
				}

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

				sess[key] = value

				if err := store.Put(w, r, sess); err != nil {
					http.Error(w, "saving session failed", http.StatusInternalServerError)
					return
				}
			}

			mux.HandleFunc("GET /set", setHandler)

			mux.HandleFunc("GET /get", func(w http.ResponseWriter, r *http.Request) {
				sess := map[string]string{}

				loaded, err := store.Get(r, &sess)
				t.Logf("GET /set: loaded %t err %v", loaded, err)
				if err != nil {
					http.Error(w, "loading store failed", http.StatusInternalServerError)
					return
				}

				key := r.URL.Query().Get("key")
				if key == "" {
					t.Fatal("query with no key")
				}

				value, ok := sess[key]
				if !ok {
					http.Error(w, "key not in session", http.StatusNotFound)
					return
				}

				_, _ = w.Write([]byte(value))
			})

			mux.HandleFunc("GET /reset", func(w http.ResponseWriter, r *http.Request) {
				// delete the old one, then set a new one.
				if err := store.Delete(w, r); err != nil {
					http.Error(w, "deleting session failed", http.StatusInternalServerError)
					return
				}

				setHandler(w, r)
			})

			mux.HandleFunc("GET /clear", func(w http.ResponseWriter, r *http.Request) {
				if err := store.Delete(w, r); err != nil {
					t.Logf("delete err: %v", err)
					http.Error(w, "delete failed", http.StatusNotFound)
					return
				}
			})

			svr := httptest.NewServer(mux)
			t.Cleanup(svr.Close)

			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}

			client := &http.Client{
				Jar: jar,
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

			// duplicate the jar, so after a reset we can make sure the old
			// session still can't be loaded.
			oldJar := must(cookiejar.New(nil))
			svrURL := must(url.Parse(svr.URL))
			oldJar.SetCookies(svrURL, jar.Cookies(svrURL))
			oldClient := &http.Client{
				Jar: oldJar,
			}

			doReq(t, client, svr.URL+"/reset?key=reset1&value=value1", http.StatusOK)
			doReq(t, client, svr.URL+"/get?key=reset1", http.StatusOK)

			doReq(t, oldClient, svr.URL+"/get?key=reset1", http.StatusNotFound)

			// clear it, and make sure it doesn't work
			for _, c := range []*http.Client{client, oldClient} {
				doReq(t, c, svr.URL+"/clear", http.StatusOK)
				doReq(t, c, svr.URL+"/get?key=test1", http.StatusNotFound)
				doReq(t, c, svr.URL+"/get?key=reset1", http.StatusNotFound)
			}
		})
	}
}

func assertNoDuplicateCookies(t *testing.T, cookies []*http.Cookie) {
	t.Helper()

	seen := make(map[string]struct{})
	for _, cookie := range cookies {
		if _, exists := seen[cookie.Name]; exists {
			t.Errorf("cookie %s has multiple set's", cookie.Name)
		}
		seen[cookie.Name] = struct{}{}
	}
}

func doReq(t *testing.T, client *http.Client, url string, wantStatus int) string {
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
	// TODO - check how much of a problem this is. It's likely a delete then
	// create, one should be expiring and a new one should be set. It's hard to
	// avoid this though.
	// assertNoDuplicateCookies(t, resp.Cookies())
	return string(bb)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(fmt.Sprintf("error: %v", err))
	}
	return v
}
