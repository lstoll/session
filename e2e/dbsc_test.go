package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
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
	"lds.li/session"
)

type sessionData struct {
	User string
}

const testDBSCBoundCookieName = "__Host-session-id-bound"

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

	baseURL := os.Getenv("DBSC_TEST_URL")
	if baseURL == "" {
		baseURL = startDBSCTestServer(t)
	} else {
		t.Logf("using external DBSC test server at %s", baseURL)
	}

	runDBSCChromeFlow(t, baseURL)
}

func startDBSCTestServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	baseURL := "https://127.0.0.1:" + port

	mgr := newDBSCTestManager(t, baseURL)

	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		data := sess.Get()
		data.User = "alice"
		sess.Set(data)
		_, _ = w.Write([]byte("logged in"))
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		if sess.Get().User != "alice" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("protected content")); err != nil {
			t.Errorf("write protected body: %v", err)
		}
	})
	mux.HandleFunc("/bound", func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		if sess.IsDeviceBound() {
			w.Write([]byte("bound"))
			return
		}
		w.Write([]byte("unbound"))
	})
	mux.HandleFunc("/expire-bound-cookie", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     testDBSCBoundCookieName,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Unix(1, 0),
			MaxAge:   -1,
		})
		http.Redirect(w, r, "/protected", http.StatusTemporaryRedirect)
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

func newDBSCTestManager(t *testing.T, origin string) *session.Manager[sessionData] {
	t.Helper()
	kv := session.NewMemoryKV()
	opts := &session.KVManagerOpts[sessionData]{
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
	}
	mgr, err := session.NewKVManager[sessionData](kv, opts)
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
	creationEvents := make(chan *network.EventDeviceBoundSessionEventOccurred, 8)
	refreshEvents := make(chan *network.EventDeviceBoundSessionEventOccurred, 8)
	chromedp.ListenTarget(ctx, func(event any) {
		eventDetails, ok := event.(*network.EventDeviceBoundSessionEventOccurred)
		if !ok {
			return
		}
		switch {
		case eventDetails.CreationEventDetails != nil:
			select {
			case creationEvents <- eventDetails:
			default:
			}
		case eventDetails.RefreshEventDetails != nil:
			select {
			case refreshEvents <- eventDetails:
			default:
			}
		}
	})

	// 1. Perform login
	err := chromedp.Run(ctx,
		network.Enable(),
		network.EnableDeviceBoundSessions(true),
		chromedp.Navigate(baseURL+"/login"),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	select {
	case event := <-creationEvents:
		if !event.Succeeded || event.CreationEventDetails.FetchResult != network.DeviceBoundSessionFetchResultSuccess {
			t.Fatalf(
				"DBSC creation event = succeeded %v, fetch result %q, failed request %#v",
				event.Succeeded,
				event.CreationEventDetails.FetchResult,
				event.CreationEventDetails.FailedRequest,
			)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for successful DBSC creation event")
	}

	// 2. Verify the server persisted the device binding.
	var bound string
	err = chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/bound"),
		chromedp.Text(`body`, &bound, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("check bound failed: %v", err)
	}
	if bound != "bound" {
		t.Fatalf("device binding state = %q, want bound", bound)
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

	// 4. Expire the protected cookie and follow the redirect to an in-scope
	// resource. Chrome should defer that request, refresh the DBSC session, and
	// retry it with a rotated cookie.
	boundCookieBefore := chromeCookieValue(t, ctx, baseURL, testDBSCBoundCookieName)
	drainDBSCRefreshEvents(refreshEvents)
	body = ""
	err = chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/expire-bound-cookie"),
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
		chromedp.Text(`body`, &body, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("navigation after bound cookie expiry failed: %v", err)
	}
	if !strings.Contains(body, "protected") {
		t.Fatalf("unexpected post-refresh page body: %q", body)
	}

	select {
	case event := <-refreshEvents:
		if !event.Succeeded || event.RefreshEventDetails.RefreshResult != network.RefreshEventDetailsRefreshResultRefreshed {
			t.Fatalf(
				"DBSC refresh event = succeeded %v, result %q, fetch result %q, failed request %#v",
				event.Succeeded,
				event.RefreshEventDetails.RefreshResult,
				event.RefreshEventDetails.FetchResult,
				event.RefreshEventDetails.FailedRequest,
			)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for successful DBSC refresh event")
	}

	boundCookieAfter := chromeCookieValue(t, ctx, baseURL, testDBSCBoundCookieName)
	if boundCookieAfter == boundCookieBefore {
		t.Fatal("DBSC refresh did not rotate the bound cookie")
	}
}

func chromeCookieValue(t *testing.T, ctx context.Context, url, name string) string {
	t.Helper()
	var value string
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		cookies, err := network.GetCookies().WithURLs([]string{url}).Do(ctx)
		if err != nil {
			return err
		}
		for _, cookie := range cookies {
			if cookie.Name == name {
				value = cookie.Value
				return nil
			}
		}
		return fmt.Errorf("cookie %q not found", name)
	}))
	if err != nil {
		t.Fatalf("read Chrome cookie: %v", err)
	}
	return value
}

func drainDBSCRefreshEvents(events <-chan *network.EventDeviceBoundSessionEventOccurred) {
	for {
		select {
		case <-events:
		default:
			return
		}
	}
}

// TestLoginResponseIncludesSecureSessionRegistration checks that the session
// stack emits DBSC registration headers over HTTPS (no Chrome DBSC required).
func TestLoginResponseIncludesSecureSessionRegistration(t *testing.T) {
	kv := session.NewMemoryKV()
	mgr, err := session.NewKVManager[sessionData](kv, &session.KVManagerOpts[sessionData]{
		IdleTimeout:          time.Hour,
		DBSCRefreshInterval:  5 * time.Minute,
		DBSCRegistrationPath: "/register",
		DBSCOrigin:           "https://example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		data := sess.Get()
		data.User = "alice"
		sess.Set(data)
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
