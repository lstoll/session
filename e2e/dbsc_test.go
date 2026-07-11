package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"lds.li/session"
)

func chromeDBSCAllocatorOptions(userDataDir string) []chromedp.ExecAllocatorOption {
	co := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("enable-features", "DeviceBoundSessions,DeviceBoundSessionsDevTools,EnableBoundSessionCredentialsSoftwareKeysForManualTesting"),
		chromedp.Flag("ignore-certificate-errors", "1"),
	)
	if userDataDir != "" {
		co = append(co, chromedp.Flag("user-data-dir", userDataDir))
	}
	if path := os.Getenv("CHROME_PATH"); path != "" {
		co = append(co, chromedp.ExecPath(path))
	} else if runtime.GOOS == "darwin" {
		co = append(co, chromedp.ExecPath("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
	}
	if os.Getenv("E2E_HEADED") == "1" {
		co = append(co, chromedp.Flag("headless", false))
	} else {
		co = append(co, chromedp.Flag("headless", "new"))
	}
	return co
}

func TestDBSC_E2E(t *testing.T) {
	if os.Getenv("CHROME_PATH") == "" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("DBSC e2e needs Google Chrome on macOS or Windows (set CHROME_PATH to override)")
	}

	tests := []struct {
		name      string
		useCookie bool
	}{
		{name: "KV_Store", useCookie: false},
		{name: "Cookie_Store", useCookie: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseURL := os.Getenv("DBSC_TEST_URL")
			if baseURL == "" {
				baseURL = startDBSCTestServer(t, tc.useCookie)
			} else {
				t.Logf("using external DBSC test server at %s", baseURL)
			}

			runDBSCChromeFlow(t, baseURL)
		})
	}
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

func startDBSCTestServer(t *testing.T, useCookie bool) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	baseURL := "https://127.0.0.1:" + port

	mgr := newDBSCTestManager(t, useCookie, baseURL)

	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		sess := session.MustFromContext(r.Context())
		sess.Set("user", "alice")
		http.Redirect(w, r, "/protected", http.StatusSeeOther)
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		sess := session.MustFromContext(r.Context())
		if sess.Get("user") != "alice" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("protected content")); err != nil {
			t.Errorf("write protected body: %v", err)
		}
	})
	mux.HandleFunc("/bound", func(w http.ResponseWriter, r *http.Request) {
		sess := session.MustFromContext(r.Context())
		if sess.IsDeviceBound() {
			w.Write([]byte("bound"))
			return
		}
		w.Write([]byte("unbound"))
	})

	ts := httptest.NewUnstartedServer(mgr.Wrap(mux))
	ts.Listener = ln
	ts.StartTLS()
	t.Cleanup(ts.Close)
	t.Logf("test server at %s", baseURL)

	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	preflightResp, err := client.Get(baseURL + "/login")
	if err != nil {
		t.Fatalf("preflight get: %v", err)
	}
	preflightResp.Body.Close()
	t.Logf("preflight login %d reg=%q cookie=%q", preflightResp.StatusCode,
		preflightResp.Header.Get("Secure-Session-Registration"),
		preflightResp.Header.Get("Set-Cookie"))

	return baseURL
}

func newDBSCTestManager(t *testing.T, useCookie bool, origin string) *session.Manager {
	t.Helper()
	if useCookie {
		opts := &session.CookieManagerOpts{
			ManagerOpts: session.ManagerOpts{
				IdleTimeout:          1 * time.Hour,
				DBSCRefreshInterval:  5 * time.Minute,
				DBSCRegistrationPath: "/register",
				DBSCRefreshPath:      "/dbsc/refresh",
				DBSCOrigin:           origin,
				CookieOpts: &session.SessionCookieOpts{
					Name:    "__Host-session",
					Path:    "/",
					Persist: true,
				},
			},
		}
		aeadKey := newTestAEAD(t)
		mgr, err := session.NewCookieManager(aeadKey, opts)
		if err != nil {
			t.Fatalf("failed to create cookie manager: %v", err)
		}
		return mgr
	}

	kv := session.NewMemoryKV()
	opts := &session.KVManagerOpts{
		ManagerOpts: session.ManagerOpts{
			IdleTimeout:          1 * time.Hour,
			DBSCRefreshInterval:  5 * time.Minute,
			DBSCRegistrationPath: "/register",
			DBSCRefreshPath:      "/dbsc/refresh",
			DBSCOrigin:           origin,
			CookieOpts: &session.SessionCookieOpts{
				Name:    "__Host-session-id",
				Path:    "/",
				Persist: true,
			},
		},
	}
	mgr, err := session.NewKVManager(kv, opts)
	if err != nil {
		t.Fatalf("failed to create kv manager: %v", err)
	}
	return mgr
}

func runDBSCChromeFlow(t *testing.T, baseURL string) {
	co := chromeDBSCAllocatorOptions("")

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), co...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// 1. Perform login
	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(baseURL+"/login"),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// 2. Poll /bound until it returns "bound" (timeout after 10s)
	var bound string
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := chromedp.Run(ctx,
			chromedp.Navigate(baseURL+"/bound"),
			chromedp.Text(`body`, &bound, chromedp.ByQuery),
		)
		if err != nil {
			t.Fatalf("check bound failed: %v", err)
		}
		if bound == "bound" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for device-bound session; got %q", bound)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// 3. Verify access to protected resource
	var body string
	err = chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/protected"),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
		chromedp.Text(`body`, &body, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("protected navigation failed: %v", err)
	}

	if !strings.Contains(body, "protected") {
		t.Fatalf("unexpected protected page body: %q", body)
	}
}

// TestLoginResponseIncludesSecureSessionRegistration checks that the session
// stack emits DBSC registration headers over HTTPS (no Chrome DBSC required).
func TestLoginResponseIncludesSecureSessionRegistration(t *testing.T) {
	kv := session.NewMemoryKV()
	mgr, err := session.NewKVManager(kv, &session.KVManagerOpts{
		ManagerOpts: session.ManagerOpts{
			IdleTimeout:          time.Hour,
			DBSCRefreshInterval:  5 * time.Minute,
			DBSCRegistrationPath: "/register",
			DBSCOrigin:           "https://example.test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		s := session.MustFromContext(r.Context())
		s.Set("u", 1)
		w.Write([]byte("ok"))
	})
	ts := httptest.NewTLSServer(mgr.Wrap(mux))
	defer ts.Close()
	c := ts.Client()
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := c.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	reg := resp.Header.Get("Secure-Session-Registration")
	if reg == "" {
		t.Fatal("expected Secure-Session-Registration response header")
	}
	if !strings.Contains(reg, "ES256") || !strings.Contains(reg, "/register") || !strings.Contains(reg, "challenge=") {
		t.Fatalf("unexpected Secure-Session-Registration value: %q", reg)
	}
}
