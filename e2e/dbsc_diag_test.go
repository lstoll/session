//go:build dbscdiag

package e2e

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// TestDBSC_Diag logs Chrome network activity against a real HTTPS server.
// Run: go test -tags dbscdiag -run TestDBSC_Diag -v -timeout 2m
func TestDBSC_Diag(t *testing.T) {
	base := os.Getenv("DBSC_TEST_URL")
	if base == "" {
		t.Skip("set DBSC_TEST_URL (e.g. https://localhost:8443) and run dbsc-tester first")
	}

	co := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
		chromedp.Flag("enable-features", chromeDBSCFeatures),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("allow-insecure-localhost", true),
	)
	if os.Getenv("DBSC_HEADLESS") == "1" {
		co = append(co, chromedp.Flag("headless", "new"))
	} else {
		co = append(co, chromedp.Flag("headless", false))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), co...)
	defer cancel()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			t.Logf("REQ %s %s", e.Request.Method, e.Request.URL)
			for k, v := range e.Request.Headers {
				kl := strings.ToLower(k)
				if strings.Contains(kl, "secure-session") || strings.Contains(kl, "sec-session") || strings.Contains(kl, "sec-secure") {
					t.Logf("  hdr %s: %v", k, v)
				}
			}
		case *network.EventResponseReceived:
			t.Logf("RES %d %s", e.Response.Status, e.Response.URL)
			for k, v := range e.Response.Headers {
				kl := strings.ToLower(k)
				if strings.Contains(kl, "secure-session") || strings.Contains(kl, "set-cookie") {
					t.Logf("  hdr %s: %v", k, v)
				}
			}
		}
	})

	if err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(base+"/login"),
		chromedp.Sleep(8*time.Second),
		chromedp.Navigate(base+"/protected"),
		chromedp.Sleep(3*time.Second),
	); err != nil {
		t.Fatal(err)
	}
}
