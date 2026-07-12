package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func generateJWTSignature(t *testing.T, privKey *ecdsa.PrivateKey, header, payload string) string {
	hash := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	return base64.RawURLEncoding.EncodeToString(sigBytes)
}

func ecCoordBytes(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) > size {
		panic("coordinate exceeds field")
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// es256JWKJSON returns a JSON object (for embedding in a JWT header) for tests only.
func es256JWKJSON(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	if pub.Curve != elliptic.P256() {
		t.Fatal("P-256 only")
	}
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := ecCoordBytes(pub.X, byteLen)
	y := ecCoordBytes(pub.Y, byteLen)
	return `{"kty":"EC","crv":"P-256","alg":"ES256","x":"` +
		base64.RawURLEncoding.EncodeToString(x) + `","y":"` +
		base64.RawURLEncoding.EncodeToString(y) + `"}`
}

func challengeFromSecureSessionRegistration(t *testing.T, reg string) string {
	t.Helper()
	const prefix = `challenge="`
	i := strings.Index(reg, prefix)
	if i < 0 {
		t.Fatalf("no challenge in %q", reg)
	}
	i += len(prefix)
	j := strings.IndexByte(reg[i:], '"')
	if j < 0 {
		t.Fatalf("unterminated challenge in %q", reg)
	}
	return reg[i : i+j]
}

func TestDBSC(t *testing.T) {
	t.Run("KV Store", func(t *testing.T) {
		t.Run("refresh_endpoint", func(t *testing.T) {
			testDBSCRefreshEndpoint(t, 5*time.Minute, false)
		})
		t.Run("in_band_challenge", func(t *testing.T) {
			testDBSCInBandChallenge(t, time.Millisecond, false)
		})
		t.Run("skipped_header_rejected", func(t *testing.T) {
			testDBSCSkippedRejected(t, false)
		})
		t.Run("registration_chrome_jwk", func(t *testing.T) {
			testDBSCRegistrationChromeJWK(t, false)
		})
		t.Run("registration_stale_iat_rejected", func(t *testing.T) {
			testDBSCRegistrationStaleIATRejected(t, false)
		})
		t.Run("registration_cross_site_rejected", func(t *testing.T) {
			testDBSCRegistrationCrossSiteRejected(t, false)
		})
	})
}

func TestDBSCConcurrentRefreshChallenges(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	store := &kvStore{kv: kv}
	sctx := &Session{sessdata: persistedSession{DBSCSessionID: "dbsc-session"}}
	req := httptest.NewRequest(http.MethodPost, "/dbsc/refresh", nil)

	first, err := store.generateChallenge(req, sctx, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.generateChallenge(req, sctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("independently generated challenges must differ")
	}
	if err := store.verifyChallenge(req, sctx, first, false); err != nil {
		t.Fatalf("first challenge was overwritten: %v", err)
	}
	if err := store.verifyChallenge(req, sctx, second, false); err != nil {
		t.Fatalf("second challenge is not valid: %v", err)
	}

	if err := store.consumeChallenge(req, sctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyChallenge(req, sctx, first, false); err == nil {
		t.Fatal("consumed challenge remains valid")
	}
	if err := store.verifyChallenge(req, sctx, second, false); err != nil {
		t.Fatalf("consuming first challenge invalidated second: %v", err)
	}
}

func testDBSCRegistrationCrossSiteRejected(t *testing.T, useCookie bool) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute, useCookie)

	req0 := newTestRequest(http.MethodGet, "/start", nil)
	rr0 := httptest.NewRecorder()
	handler.ServeHTTP(rr0, req0)
	regChallenge := challengeFromSecureSessionRegistration(t, rr0.Header().Get("Secure-Session-Registration"))
	cookies := extractCookies(rr0)

	regJWT := dbscProofJWT(t, privKey, regChallenge, true)
	req1 := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req1, cookies)
	req1.Header.Set("Secure-Session-Response", regJWT)
	req1.Header.Set("Sec-Fetch-Site", "cross-site")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusForbidden {
		t.Fatalf("cross-site registration: got %v want 403", rr1.Code)
	}
}

func testDBSCRegistrationStaleIATRejected(t *testing.T, useCookie bool) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute, useCookie)

	req0 := newTestRequest(http.MethodGet, "/start", nil)
	rr0 := httptest.NewRecorder()
	handler.ServeHTTP(rr0, req0)
	regChallenge := challengeFromSecureSessionRegistration(t, rr0.Header().Get("Secure-Session-Registration"))
	cookies := extractCookies(rr0)

	regJWT := dbscProofJWTWithIAT(t, privKey, regChallenge, time.Now().Add(-10*time.Minute), true)
	req1 := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req1, cookies)
	req1.Header.Set("Secure-Session-Response", regJWT)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Fatalf("registration with stale iat: got %v want 401", rr1.Code)
	}
}

func testDBSCRegistrationChromeJWK(t *testing.T, useCookie bool) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute, useCookie)

	req0 := newTestRequest(http.MethodGet, "/start", nil)
	rr0 := httptest.NewRecorder()
	handler.ServeHTTP(rr0, req0)
	regChallenge := challengeFromSecureSessionRegistration(t, rr0.Header().Get("Secure-Session-Registration"))
	cookies := extractCookies(rr0)

	regJWT := dbscProofJWTJTIOOnly(t, privKey, regChallenge, true, false)
	req1 := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req1, cookies)
	req1.Header.Set("Secure-Session-Response", regJWT)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("registration with chrome-style jwk: got %v %s", rr1.Code, rr1.Body.String())
	}
}

func testDBSCRegistrationChallengeSessionBound(t *testing.T, useCookie bool) {
	t.Helper()
	if !useCookie {
		t.Skip("registration challenge binding is cookie-store specific")
	}

	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute, useCookie)

	reqA := newTestRequest(http.MethodGet, "/start", nil)
	rrA := httptest.NewRecorder()
	handler.ServeHTTP(rrA, reqA)
	challengeA := challengeFromSecureSessionRegistration(t, rrA.Header().Get("Secure-Session-Registration"))
	cookiesA := extractCookies(rrA)

	reqB := newTestRequest(http.MethodGet, "/start", nil)
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	cookiesB := extractCookies(rrB)

	regJWT := dbscProofJWT(t, privKey, challengeA, true)
	reqCross := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(reqCross, cookiesB)
	reqCross.Header.Set("Secure-Session-Response", regJWT)
	rrCross := httptest.NewRecorder()
	handler.ServeHTTP(rrCross, reqCross)
	if rrCross.Code != http.StatusUnauthorized {
		t.Fatalf("cross-session registration challenge: got %v want 401", rrCross.Code)
	}

	regJWT = dbscProofJWT(t, privKey, challengeA, true)
	reqOK := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(reqOK, cookiesA)
	reqOK.Header.Set("Secure-Session-Response", regJWT)
	rrOK := httptest.NewRecorder()
	handler.ServeHTTP(rrOK, reqOK)
	if rrOK.Code != http.StatusOK {
		t.Fatalf("same-session registration challenge: got %v %s", rrOK.Code, rrOK.Body.String())
	}
}

func testDBSCRefreshEndpoint(t *testing.T, refreshInterval time.Duration, useCookie bool) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, refreshInterval, useCookie)

	_, dbscSessionID, cookies := completeDBSCRegistration(t, handler, privKey, nil)

	reqRefresh := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
	addCookies(reqRefresh, cookies)
	reqRefresh.Header.Set("Sec-Secure-Session-Id", `"`+dbscSessionID+`"`)
	rrRefresh := httptest.NewRecorder()
	handler.ServeHTTP(rrRefresh, reqRefresh)
	if rrRefresh.Code != http.StatusForbidden {
		t.Fatalf("refresh without proof: got %v want 403", rrRefresh.Code)
	}
	challenge := rrRefresh.Header().Get("Secure-Session-Challenge")
	if challenge == "" {
		t.Fatal("expected Secure-Session-Challenge on refresh")
	}
	challengeNonce := challengeNonceFromHeader(t, challenge)

	cookies = mergeCookies(cookies, extractCookies(rrRefresh))

	refreshJWT := dbscProofJWT(t, privKey, challengeNonce, false)
	reqRefresh2 := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
	addCookies(reqRefresh2, cookies)
	reqRefresh2.Header.Set("Sec-Secure-Session-Id", `"`+dbscSessionID+`"`)
	reqRefresh2.Header.Set("Secure-Session-Response", `"`+refreshJWT+`"`)
	rrRefresh2 := httptest.NewRecorder()
	handler.ServeHTTP(rrRefresh2, reqRefresh2)
	if rrRefresh2.Code != http.StatusOK {
		t.Fatalf("refresh with proof: got %v %s", rrRefresh2.Code, rrRefresh2.Body.String())
	}
	var instructions map[string]any
	if err := json.Unmarshal(rrRefresh2.Body.Bytes(), &instructions); err != nil {
		t.Fatalf("refresh response json: %v", err)
	}
	if instructions["session_identifier"] != dbscSessionID {
		t.Fatalf("refresh session_identifier: got %v want %q", instructions["session_identifier"], dbscSessionID)
	}

	cookies = mergeCookies(cookies, extractCookies(rrRefresh2))

	reqProtected := newTestRequest(http.MethodGet, "/protected", nil)
	addCookies(reqProtected, cookies)
	rrProtected := httptest.NewRecorder()
	handler.ServeHTTP(rrProtected, reqProtected)
	if rrProtected.Code != http.StatusOK {
		t.Fatalf("protected after refresh: got %v", rrProtected.Code)
	}
}

func testDBSCSkippedRejected(t *testing.T, useCookie bool) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute, useCookie)

	_, dbscSessionID, cookies := completeDBSCRegistration(t, handler, privKey, nil)

	t.Run("in_band", func(t *testing.T) {
		req := newTestRequest(http.MethodGet, "/protected", nil)
		addCookies(req, cookies)
		req.Header.Set("Sec-Secure-Session-Skipped", "?1")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("in-band with Sec-Secure-Session-Skipped: got %v want 401", rr.Code)
		}
	})

	t.Run("refresh", func(t *testing.T) {
		req := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
		addCookies(req, cookies)
		req.Header.Set("Sec-Secure-Session-Id", `"`+dbscSessionID+`"`)
		req.Header.Set("Sec-Secure-Session-Skipped", "?1")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("refresh with Sec-Secure-Session-Skipped: got %v want 401", rr.Code)
		}
	})
}

func testDBSCInBandChallenge(t *testing.T, refreshInterval time.Duration, useCookie bool) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, refreshInterval, useCookie)

	_, dbscSessionID, cookies := completeDBSCRegistration(t, handler, privKey, nil)

	time.Sleep(refreshInterval + time.Millisecond)

	req2 := newTestRequest(http.MethodGet, "/protected", nil)
	// Keep all cookies (including bound) to ensure expired DBSCExpiration in the
	// session cookie cannot be bypassed by replaying a stolen cookie pair.
	addCookies(req2, cookies)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for expired DBSC session, got %v", rr2.Code)
	}
	challenge := rr2.Header().Get("Secure-Session-Challenge")
	if challenge == "" {
		t.Fatal("expected Secure-Session-Challenge header")
	}
	challengeNonce := challengeNonceFromHeader(t, challenge)
	if !strings.Contains(challenge, dbscSessionID) {
		t.Fatalf("challenge id should include session id %q, got %q", dbscSessionID, challenge)
	}

	oldSessionCookie := findCookieByName(cookies, "__Host-session-id")
	if oldSessionCookie == nil {
		t.Fatal("missing __Host-session-id cookie before rotation")
	}
	oldValue := oldSessionCookie.Value

	cookies = mergeCookies(cookies, extractCookies(rr2))

	refreshJWT := dbscProofJWT(t, privKey, challengeNonce, false)
	req3 := newTestRequest(http.MethodGet, "/protected", nil)
	addCookies(req3, cookies)
	req3.Header.Set("Secure-Session-Response", refreshJWT)
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("expected 200 after valid in-band challenge, got %v body: %s", rr3.Code, rr3.Body.String())
	}

	cookies = mergeCookies(cookies, extractCookies(rr3))

	newSessionCookie := findCookieByName(cookies, "__Host-session-id")
	if newSessionCookie == nil {
		t.Fatal("missing __Host-session-id cookie after rotation")
	}
	if newSessionCookie.Value == oldValue {
		t.Fatal("expected session cookie to rotate after successful in-band challenge")
	}
}

func setupDBSCHandler(t *testing.T, kv *memoryKV, refreshInterval time.Duration, useCookie bool) (*Manager, http.Handler, *ecdsa.PrivateKey, *http.Cookie) {
	t.Helper()
	var mgr *Manager
	var err error

	if useCookie {
		aead := newTestAEAD(t)
		opts := &CookieManagerOpts{
			ManagerOpts: ManagerOpts{
				IdleTimeout:          time.Hour,
				DBSCRefreshInterval:  refreshInterval,
				DBSCRegistrationPath: "/register",
				DBSCRefreshPath:      "/dbsc/refresh",
				DBSCOrigin:           "https://example.com",
				CookieOpts: &SessionCookieOpts{
					Name: "__Host-session-id",
					Path: "/",
				},
			},
		}
		mgr, err = NewCookieManager(aead, opts)
	} else {
		opts := &KVManagerOpts{
			ManagerOpts: ManagerOpts{
				IdleTimeout:          time.Hour,
				DBSCRefreshInterval:  refreshInterval,
				DBSCRegistrationPath: "/register",
				DBSCRefreshPath:      "/dbsc/refresh",
				DBSCOrigin:           "https://example.com",
			},
		}
		mgr, err = NewKVManager(kv, opts)
	}

	if err != nil {
		t.Fatalf("creating manager: %v", err)
	}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	handler := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := mgr.FromContext(r.Context())
		switch r.URL.Path {
		case "/start":
			sess.Set("bootstrap", "1")
			w.WriteHeader(http.StatusOK)
		default:
			if sess.Get("bootstrap") == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}
	}))
	return mgr, handler, privKey, nil
}

func completeDBSCRegistration(t *testing.T, handler http.Handler, privKey *ecdsa.PrivateKey, sessionCookies []*http.Cookie) (regChallenge, dbscSessionID string, cookies []*http.Cookie) {
	t.Helper()
	req0 := newTestRequest(http.MethodGet, "/start", nil)
	addCookies(req0, sessionCookies)
	rr0 := httptest.NewRecorder()
	handler.ServeHTTP(rr0, req0)
	if rr0.Code != http.StatusOK {
		t.Fatalf("start: %v", rr0.Code)
	}
	reg := rr0.Header().Get("Secure-Session-Registration")
	regChallenge = challengeFromSecureSessionRegistration(t, reg)
	cookies = mergeCookies(sessionCookies, extractCookies(rr0))

	regJWT := dbscProofJWT(t, privKey, regChallenge, true)
	req1 := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req1, cookies)
	req1.Header.Set("Secure-Session-Response", regJWT)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("registration failed: %v %s", rr1.Code, rr1.Body.String())
	}
	var instructions map[string]any
	if err := json.Unmarshal(rr1.Body.Bytes(), &instructions); err != nil {
		t.Fatalf("registration json: %v", err)
	}
	id, _ := instructions["session_identifier"].(string)
	if id == "" {
		t.Fatal("missing session_identifier in registration response")
	}
	cookies = mergeCookies(cookies, extractCookies(rr1))
	return regChallenge, id, cookies
}

func dbscProofJWT(t *testing.T, privKey *ecdsa.PrivateKey, jti string, withJWK bool) string {
	return dbscProofJWTWithIAT(t, privKey, jti, time.Now(), withJWK)
}

func dbscProofJWTWithIAT(t *testing.T, privKey *ecdsa.PrivateKey, jti string, iat time.Time, withJWK bool) string {
	return dbscProofJWTWithJWKAlgAndIAT(t, privKey, jti, iat, withJWK, true)
}

// dbscProofJWTWithJWKAlg builds a DBSC proof; chromeStyleJWK omits alg from the embedded JWK.
func dbscProofJWTWithJWKAlg(t *testing.T, privKey *ecdsa.PrivateKey, jti string, withJWK, jwkIncludesAlg bool) string {
	return dbscProofJWTWithJWKAlgAndIAT(t, privKey, jti, time.Now(), withJWK, jwkIncludesAlg)
}

func dbscProofJWTWithJWKAlgAndIAT(t *testing.T, privKey *ecdsa.PrivateKey, jti string, iat time.Time, withJWK, jwkIncludesAlg bool) string {
	t.Helper()
	var headerJSON string
	if withJWK {
		jwk := es256JWKJSON(t, &privKey.PublicKey)
		if !jwkIncludesAlg {
			jwk = strings.Replace(jwk, `"alg":"ES256",`, "", 1)
		}
		headerJSON = `{"alg":"ES256","typ":"dbsc+jwt","jwk":` + jwk + `}`
	} else {
		headerJSON = `{"alg":"ES256","typ":"dbsc+jwt"}`
	}
	payloadJSON := `{"jti":"` + jti + `","iat":` + fmt.Sprintf("%d", iat.Unix()) + `}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	sigB64 := generateJWTSignature(t, privKey, headerB64, payloadB64)
	return headerB64 + "." + payloadB64 + "." + sigB64
}

// dbscProofJWTJTIOOnly builds a Chrome-style proof with only jti (no iat/exp).
func dbscProofJWTJTIOOnly(t *testing.T, privKey *ecdsa.PrivateKey, jti string, withJWK, jwkIncludesAlg bool) string {
	t.Helper()
	var headerJSON string
	if withJWK {
		jwk := es256JWKJSON(t, &privKey.PublicKey)
		if !jwkIncludesAlg {
			jwk = strings.Replace(jwk, `"alg":"ES256",`, "", 1)
		}
		headerJSON = `{"alg":"ES256","typ":"dbsc+jwt","jwk":` + jwk + `}`
	} else {
		headerJSON = `{"alg":"ES256","typ":"dbsc+jwt"}`
	}
	payloadJSON := `{"jti":"` + jti + `"}`
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	sigB64 := generateJWTSignature(t, privKey, headerB64, payloadB64)
	return headerB64 + "." + payloadB64 + "." + sigB64
}

func challengeNonceFromHeader(t *testing.T, challenge string) string {
	t.Helper()
	parts := strings.SplitN(challenge, ";", 2)
	challengeNonceRaw := strings.TrimSpace(parts[0])
	return challengeNonceRaw[1 : len(challengeNonceRaw)-1]
}

func extractCookies(rr *httptest.ResponseRecorder) []*http.Cookie {
	return rr.Result().Cookies()
}

func addCookies(req *http.Request, cookies []*http.Cookie) {
	for _, c := range cookies {
		req.AddCookie(c)
	}
}

func mergeCookies(existing []*http.Cookie, newCookies []*http.Cookie) []*http.Cookie {
	m := make(map[string]*http.Cookie)
	for _, c := range existing {
		m[c.Name] = c
	}
	for _, c := range newCookies {
		if c.MaxAge == -1 || c.Value == "" {
			delete(m, c.Name)
		} else {
			m[c.Name] = c
		}
	}
	var out []*http.Cookie
	for _, c := range m {
		out = append(out, c)
	}
	return out
}

func findCookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func newTestRequest(method, target string, body io.Reader) *http.Request {
	return httptest.NewRequest(method, target, body)
}
