package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
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

// es256JWKJSON returns a JSON object (for embedding in a JWT header) for tests only.
func es256JWKJSON(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	if pub.Curve != elliptic.P256() {
		t.Fatal("P-256 only")
	}
	encoded, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 65 || encoded[0] != 4 {
		t.Fatal("unexpected P-256 public key encoding")
	}
	x := encoded[1:33]
	y := encoded[33:]
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
			testDBSCRefreshEndpoint(t, 5*time.Minute)
		})
		t.Run("in_band_challenge", func(t *testing.T) {
			testDBSCInBandChallenge(t, time.Millisecond)
		})
		t.Run("skipped_header_rejected", func(t *testing.T) {
			testDBSCSkippedRejected(t)
		})
		t.Run("registration_editor_draft_jwk", func(t *testing.T) {
			testDBSCRegistrationEditorDraftJWK(t)
		})
		t.Run("registration_optional_iat_ignored", func(t *testing.T) {
			testDBSCRegistrationOptionalIATIgnored(t)
		})
		t.Run("registration_cross_site_rejected", func(t *testing.T) {
			testDBSCRegistrationCrossSiteRejected(t)
		})
		t.Run("registration_requires_same_origin", func(t *testing.T) {
			testDBSCRegistrationRequiresSameOrigin(t)
		})
		t.Run("registration_without_challenge_rejected", func(t *testing.T) {
			testDBSCRegistrationWithoutChallengeRejected(t)
		})
		t.Run("registration_already_bound_replays_instructions", func(t *testing.T) {
			testDBSCRegistrationAlreadyBoundReplaysInstructions(t)
		})
	})
}

func TestDBSCRS256RegistrationAndRefresh(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, _, _ := setupDBSCHandler(t, kv, 5*time.Minute)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	reqStart := newTestRequest(http.MethodGet, "/start", nil)
	rrStart := httptest.NewRecorder()
	handler.ServeHTTP(rrStart, reqStart)
	registrationChallenge := challengeFromSecureSessionRegistration(t, rrStart.Header().Get("Secure-Session-Registration"))
	cookies := extractCookies(rrStart)

	reqRegistration := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(reqRegistration, cookies)
	reqRegistration.Header.Set("Secure-Session-Response", sfString(dbscJOSEProofJWT(t, jose.RS256, private, registrationChallenge, "")))
	rrRegistration := httptest.NewRecorder()
	handler.ServeHTTP(rrRegistration, reqRegistration)
	if rrRegistration.Code != http.StatusOK {
		t.Fatalf("RS256 registration: got %d %s", rrRegistration.Code, rrRegistration.Body.String())
	}
	var instructions map[string]any
	if err := json.Unmarshal(rrRegistration.Body.Bytes(), &instructions); err != nil {
		t.Fatal(err)
	}
	sessionID, _ := instructions["session_identifier"].(string)
	if sessionID == "" {
		t.Fatal("RS256 registration returned no session identifier")
	}
	cookies = mergeCookies(cookies, extractCookies(rrRegistration))

	reqChallenge := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
	addCookies(reqChallenge, cookies)
	reqChallenge.Header.Set("Sec-Secure-Session-Id", `"`+sessionID+`"`)
	rrChallenge := httptest.NewRecorder()
	handler.ServeHTTP(rrChallenge, reqChallenge)
	refreshChallenge := challengeNonceFromHeader(t, rrChallenge.Header().Get("Secure-Session-Challenge"))
	cookies = mergeCookies(cookies, extractCookies(rrChallenge))

	reqRefresh := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
	addCookies(reqRefresh, cookies)
	reqRefresh.Header.Set("Sec-Secure-Session-Id", `"`+sessionID+`"`)
	reqRefresh.Header.Set("Secure-Session-Response", sfString(dbscJOSEProofJWT(t, jose.RS256, private, refreshChallenge, sessionID)))
	rrRefresh := httptest.NewRecorder()
	handler.ServeHTTP(rrRefresh, reqRefresh)
	if rrRefresh.Code != http.StatusOK {
		t.Fatalf("RS256 refresh: got %d %s", rrRefresh.Code, rrRefresh.Body.String())
	}
}

func dbscJOSEProofJWT(t *testing.T, algorithm jose.SignatureAlgorithm, private any, challenge, subject string) string {
	t.Helper()
	return dbscJOSEProofJWTAt(t, algorithm, private, challenge, subject, time.Now())
}

func TestDBSCRecentRefreshChallenges(t *testing.T) {
	sctx := &Session[testSessionData]{sessdata: persistedSession[testSessionData]{DBSCSessionID: "dbsc-session"}}
	now := time.Now()

	first, err := issueDBSCRefreshChallenge(sctx, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := issueDBSCRefreshChallenge(sctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("independently generated challenges must differ")
	}
	if err := verifyDBSCRefreshChallenge(sctx, first, now); err != nil {
		t.Fatalf("first challenge was overwritten: %v", err)
	}
	if err := verifyDBSCRefreshChallenge(sctx, second, now); err != nil {
		t.Fatalf("second challenge is not valid: %v", err)
	}

	consumeDBSCRefreshChallenge(sctx, first, now)
	if err := verifyDBSCRefreshChallenge(sctx, first, now); err == nil {
		t.Fatal("consumed challenge remains valid")
	}
	if err := verifyDBSCRefreshChallenge(sctx, second, now); err != nil {
		t.Fatalf("consuming first challenge invalidated second: %v", err)
	}
}

func TestDBSCStructuredStrings(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  string
		ok    bool
	}{
		{input: `"proof"`, want: "proof", ok: true},
		{input: `"proof";ignored=?1`, want: "proof", ok: true},
		{input: `"a\\\"b"`, want: `a\"b`, ok: true},
		{input: "proof"},
		{input: `"unterminated`},
		{input: `"bad\q"`},
	} {
		got, ok := parseSFString(tt.input)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseSFString(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.ok)
		}
	}
	if got := sfString(`a\"b`); got != `"a\\\"b"` {
		t.Fatalf("sfString escaped value = %q", got)
	}
}

func TestDBSCSessionIDHeader(t *testing.T) {
	for _, tt := range []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{name: "draft sf-string", header: `"SESSION234567"`, want: "SESSION234567", ok: true},
		{name: "Chrome raw identifier", header: "2SESSION234567", want: "2SESSION234567", ok: true},
		{name: "empty"},
		{name: "whitespace", header: "SESSION ID"},
		{name: "parameters on raw value", header: "SESSION;other"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/dbsc/refresh", nil)
			if tt.header != "" {
				r.Header.Set("Sec-Secure-Session-Id", tt.header)
			}
			got, ok := dbscSessionIDHeader(r)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("dbscSessionIDHeader() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestDBSCSkippedSessionMatching(t *testing.T) {
	for _, tt := range []struct {
		name      string
		headers   []string
		sessionID string
		want      bool
	}{
		{
			name:      "matching item",
			headers:   []string{`quota_exceeded;session_identifier="session-1"`},
			sessionID: "session-1",
			want:      true,
		},
		{
			name:      "matching item in list",
			headers:   []string{`unreachable;session_identifier="other", server_error;detail="retry, later";session_identifier="session-1"`},
			sessionID: "session-1",
			want:      true,
		},
		{
			name:      "matching item across fields",
			headers:   []string{`unreachable;session_identifier="other"`, `quota_exceeded;session_identifier="session-1"`},
			sessionID: "session-1",
			want:      true,
		},
		{
			name:      "different session",
			headers:   []string{`quota_exceeded;session_identifier="other"`},
			sessionID: "session-1",
		},
		{
			name:      "missing identifier",
			headers:   []string{`quota_exceeded`},
			sessionID: "session-1",
		},
		{
			name:      "malformed list",
			headers:   []string{`quota_exceeded;session_identifier="session-1`},
			sessionID: "session-1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := newTestRequest(http.MethodGet, "/", nil)
			for _, header := range tt.headers {
				req.Header.Add("Secure-Session-Skipped", header)
			}
			if got := dbscSessionSkipped(req, tt.sessionID); got != tt.want {
				t.Fatalf("dbscSessionSkipped() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManagerCookieMaxAgeRoundsUp(t *testing.T) {
	for _, tt := range []struct {
		remaining time.Duration
		want      int
	}{
		{remaining: -time.Nanosecond, want: -1},
		{remaining: 0, want: -1},
		{remaining: time.Nanosecond, want: 1},
		{remaining: time.Second, want: 1},
		{remaining: time.Second + time.Nanosecond, want: 2},
	} {
		if got := managerCookieMaxAge(tt.remaining); got != tt.want {
			t.Errorf("managerCookieMaxAge(%v) = %d, want %d", tt.remaining, got, tt.want)
		}
	}
}

func TestDBSCOptionsValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts managerOpts[struct{}]
	}{
		{name: "negative interval", opts: managerOpts[struct{}]{DBSCRefreshInterval: -time.Second}},
		{name: "missing origin", opts: managerOpts[struct{}]{DBSCRefreshInterval: time.Minute}},
		{name: "insecure origin", opts: managerOpts[struct{}]{DBSCRefreshInterval: time.Minute, DBSCOrigin: "http://example.com"}},
		{name: "origin path", opts: managerOpts[struct{}]{DBSCRefreshInterval: time.Minute, DBSCOrigin: "https://example.com/path"}},
		{name: "relative registration path", opts: managerOpts[struct{}]{DBSCRefreshInterval: time.Minute, DBSCOrigin: "https://example.com", DBSCRegistrationPath: "register"}},
		{name: "refresh query", opts: managerOpts[struct{}]{DBSCRefreshInterval: time.Minute, DBSCOrigin: "https://example.com", DBSCRefreshPath: "/refresh?x=1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateDBSCOpts(tt.opts); err == nil {
				t.Fatal("invalid DBSC options accepted")
			}
		})
	}
	if err := validateDBSCOpts(managerOpts[struct{}]{
		DBSCRefreshInterval:  time.Minute,
		DBSCOrigin:           "https://example.com",
		DBSCRegistrationPath: "/register",
		DBSCRefreshPath:      "/refresh",
	}); err != nil {
		t.Fatalf("valid DBSC options rejected: %v", err)
	}
}

func TestDBSCRecentRefreshChallengesAreBoundedAndExpire(t *testing.T) {
	sctx := &Session[testSessionData]{sessdata: persistedSession[testSessionData]{DBSCSessionID: "dbsc-session"}}
	now := time.Now()
	var oldest string
	for i := 0; i < dbscMaxRecentChallenges+1; i++ {
		challenge, err := issueDBSCRefreshChallenge(sctx, now)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			oldest = challenge
		}
	}
	if got := len(sctx.sessdata.DBSCChallenges); got != dbscMaxRecentChallenges {
		t.Fatalf("stored challenges = %d, want %d", got, dbscMaxRecentChallenges)
	}
	if err := verifyDBSCRefreshChallenge(sctx, oldest, now); err == nil {
		t.Fatal("oldest challenge remained valid after bounded eviction")
	}

	latest := &sctx.sessdata.DBSCChallenges[len(sctx.sessdata.DBSCChallenges)-1]
	latest.ExpiresAt = now.Add(-time.Second)
	if err := verifyDBSCRefreshChallenge(sctx, latest.Value, now); err == nil {
		t.Fatal("expired challenge remained valid")
	}
}

func TestDBSCRegistrationAndRefreshCommitOnce(t *testing.T) {
	ckv := &countingKV{kv: &memoryKV{contents: make(map[string]kvItem)}}
	_, handler, privKey, _ := setupDBSCHandler(t, ckv, 5*time.Minute)
	_, dbscSessionID, cookies := completeDBSCRegistration(t, handler, privKey, nil)
	if got := ckv.setCount(); got != 2 {
		t.Fatalf("registration KV sets = %d, want 2 (initial session and registration)", got)
	}

	reqChallenge := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
	addCookies(reqChallenge, cookies)
	reqChallenge.Header.Set("Sec-Secure-Session-Id", `"`+dbscSessionID+`"`)
	rrChallenge := httptest.NewRecorder()
	handler.ServeHTTP(rrChallenge, reqChallenge)
	nonce := challengeNonceFromHeader(t, rrChallenge.Header().Get("Secure-Session-Challenge"))
	cookies = mergeCookies(cookies, extractCookies(rrChallenge))

	beforeProof := ckv.setCount()
	reqProof := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
	addCookies(reqProof, cookies)
	reqProof.Header.Set("Sec-Secure-Session-Id", `"`+dbscSessionID+`"`)
	reqProof.Header.Set("Secure-Session-Response", sfString(dbscProofJWT(t, privKey, nonce, dbscSessionID)))
	rrProof := httptest.NewRecorder()
	handler.ServeHTTP(rrProof, reqProof)
	if rrProof.Code != http.StatusOK {
		t.Fatalf("refresh proof: got %d %s", rrProof.Code, rrProof.Body.String())
	}
	if got := ckv.setCount() - beforeProof; got != 1 {
		t.Fatalf("refresh proof KV sets = %d, want 1", got)
	}
}

func TestDBSCInvalidInBandProofIssuesNewChallenge(t *testing.T) {
	refreshInterval := time.Millisecond
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, refreshInterval)
	_, dbscSessionID, cookies := completeDBSCRegistration(t, handler, privKey, nil)
	time.Sleep(refreshInterval + time.Millisecond)

	reqChallenge := newTestRequest(http.MethodGet, "/protected", nil)
	addCookies(reqChallenge, cookies)
	rrChallenge := httptest.NewRecorder()
	handler.ServeHTTP(rrChallenge, reqChallenge)
	nonce := challengeNonceFromHeader(t, rrChallenge.Header().Get("Secure-Session-Challenge"))

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reqProof := newTestRequest(http.MethodGet, "/protected", nil)
	addCookies(reqProof, cookies)
	reqProof.Header.Set("Secure-Session-Response", sfString(dbscProofJWT(t, wrongKey, nonce, dbscSessionID)))
	rrProof := httptest.NewRecorder()
	handler.ServeHTTP(rrProof, reqProof)
	if rrProof.Code != http.StatusForbidden {
		t.Fatalf("invalid proof: got %d, want 403", rrProof.Code)
	}
	if rrProof.Header().Get("Secure-Session-Challenge") == "" {
		t.Fatal("invalid proof did not receive a replacement challenge")
	}
}

func TestDBSCRegistrationChallengeExpires(t *testing.T) {
	now := time.Now()
	sctx := &Session[testSessionData]{}
	challenge := issueDBSCRegistrationChallenge(sctx, now)

	if err := verifyDBSCRegistrationChallenge(sctx, challenge, now); err != nil {
		t.Fatalf("fresh registration challenge rejected: %v", err)
	}
	if !hasPendingDBSCRegistrationChallenge(sctx, now) {
		t.Fatal("fresh registration challenge is not pending")
	}

	afterExpiry := now.Add(dbscChallengeTTL + time.Nanosecond)
	if err := verifyDBSCRegistrationChallenge(sctx, challenge, afterExpiry); err == nil {
		t.Fatal("expired registration challenge accepted")
	}
	if hasPendingDBSCRegistrationChallenge(sctx, afterExpiry) {
		t.Fatal("expired registration challenge remains pending")
	}

	replacement := issueDBSCRegistrationChallenge(sctx, afterExpiry)
	if replacement == challenge {
		t.Fatal("expired registration challenge was not replaced")
	}
}

func TestDBSCExpiredRegistrationChallengeIsReoffered(t *testing.T) {
	manager := &Manager[testSessionData]{opts: managerOpts[testSessionData]{
		DBSCRefreshInterval:  time.Minute,
		DBSCRegistrationPath: "/register",
	}}
	sctx := &Session[testSessionData]{sessdata: persistedSession[testSessionData]{
		DBSCRegistrationChallenge: dbscChallenge{
			Value:     "expired",
			ExpiresAt: time.Now().Add(-time.Minute),
		},
	}}
	recorder := httptest.NewRecorder()
	request := newTestRequest(http.MethodGet, "/", nil)

	manager.maybeAttachDBSCRegistrationOffer(recorder, request, sctx)

	header := recorder.Header().Get("Secure-Session-Registration")
	if header == "" {
		t.Fatal("expired registration challenge suppressed a new offer")
	}
	challenge := challengeFromSecureSessionRegistration(t, header)
	if challenge == "expired" || challenge != sctx.sessdata.DBSCRegistrationChallenge.Value {
		t.Fatalf("replacement challenge = %q, stored = %q", challenge, sctx.sessdata.DBSCRegistrationChallenge.Value)
	}
	if !sctx.sessdata.DBSCRegistrationChallenge.ExpiresAt.After(time.Now()) {
		t.Fatal("replacement registration challenge is not fresh")
	}
}

func TestInitiateDBSCRegistrationSkipsWhenBound(t *testing.T) {
	kv := &memoryKV{contents: make(map[string]kvItem)}
	mgr, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute)
	_, _, cookies := completeDBSCRegistration(t, handler, privKey, nil)

	initiate := mgr.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mgr.FromContext(r.Context()).InitiateDBSCRegistration(w, r)
		w.WriteHeader(http.StatusOK)
	}))
	req := newTestRequest(http.MethodGet, "/initiate", nil)
	addCookies(req, cookies)
	rr := httptest.NewRecorder()
	initiate.ServeHTTP(rr, req)
	if got := rr.Header().Get("Secure-Session-Registration"); got != "" {
		t.Fatalf("InitiateDBSCRegistration on bound session sent %q", got)
	}
}

func testDBSCRegistrationCrossSiteRejected(t *testing.T) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute)

	req0 := newTestRequest(http.MethodGet, "/start", nil)
	rr0 := httptest.NewRecorder()
	handler.ServeHTTP(rr0, req0)
	regChallenge := challengeFromSecureSessionRegistration(t, rr0.Header().Get("Secure-Session-Registration"))
	cookies := extractCookies(rr0)

	regJWT := dbscProofJWT(t, privKey, regChallenge, "")
	req1 := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req1, cookies)
	req1.Header.Set("Secure-Session-Response", sfString(regJWT))
	req1.Header.Set("Sec-Fetch-Site", "cross-site")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusForbidden {
		t.Fatalf("cross-site registration: got %v want 403", rr1.Code)
	}
}

func testDBSCRegistrationRequiresSameOrigin(t *testing.T) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute)

	req0 := newTestRequest(http.MethodGet, "/start", nil)
	rr0 := httptest.NewRecorder()
	handler.ServeHTTP(rr0, req0)
	regChallenge := challengeFromSecureSessionRegistration(t, rr0.Header().Get("Secure-Session-Registration"))
	cookies := extractCookies(rr0)
	regJWT := dbscProofJWT(t, privKey, regChallenge, "")

	for _, site := range []string{"", "same-site", "none"} {
		req := newTestRequest(http.MethodPost, "/register", nil)
		addCookies(req, cookies)
		req.Header.Set("Secure-Session-Response", sfString(regJWT))
		if site == "" {
			req.Header.Del("Sec-Fetch-Site")
		} else {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("Sec-Fetch-Site %q: got %v want 403", site, rr.Code)
		}
	}
}

func testDBSCRegistrationWithoutChallengeRejected(t *testing.T) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute)

	regJWT := dbscProofJWT(t, privKey, "no-such-challenge", "")
	req := newTestRequest(http.MethodPost, "/register", nil)
	req.Header.Set("Secure-Session-Response", sfString(regJWT))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("registration without challenge: got %v want 401", rr.Code)
	}
}

func testDBSCRegistrationAlreadyBoundReplaysInstructions(t *testing.T) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute)
	_, dbscSessionID, cookies := completeDBSCRegistration(t, handler, privKey, nil)

	req := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req, cookies)
	req.Header.Set("Secure-Session-Response", sfString(dbscProofJWT(t, privKey, "ignored", "")))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("already-bound registration: got %v %s", rr.Code, rr.Body.String())
	}
	var instructions map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &instructions); err != nil {
		t.Fatalf("already-bound json: %v", err)
	}
	if instructions["session_identifier"] != dbscSessionID {
		t.Fatalf("already-bound session_identifier = %v, want %q", instructions["session_identifier"], dbscSessionID)
	}
}

func testDBSCRegistrationOptionalIATIgnored(t *testing.T) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute)

	req0 := newTestRequest(http.MethodGet, "/start", nil)
	rr0 := httptest.NewRecorder()
	handler.ServeHTTP(rr0, req0)
	regChallenge := challengeFromSecureSessionRegistration(t, rr0.Header().Get("Secure-Session-Registration"))
	cookies := extractCookies(rr0)

	regJWT := dbscProofJWTWithIAT(t, privKey, regChallenge, "", time.Now().Add(-10*time.Minute))
	req1 := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req1, cookies)
	req1.Header.Set("Secure-Session-Response", sfString(regJWT))
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("registration with optional stale iat: got %v want 200", rr1.Code)
	}
}

func testDBSCRegistrationEditorDraftJWK(t *testing.T) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute)

	req0 := newTestRequest(http.MethodGet, "/start", nil)
	rr0 := httptest.NewRecorder()
	handler.ServeHTTP(rr0, req0)
	regChallenge := challengeFromSecureSessionRegistration(t, rr0.Header().Get("Secure-Session-Registration"))
	cookies := extractCookies(rr0)

	regJWT := dbscProofJWTJTIOOnly(t, privKey, regChallenge, true, false)
	req1 := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req1, cookies)
	req1.Header.Set("Secure-Session-Response", sfString(regJWT))
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("Editor Draft registration: got %v %s", rr1.Code, rr1.Body.String())
	}
}

func testDBSCRefreshEndpoint(t *testing.T, refreshInterval time.Duration) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, refreshInterval)

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

	refreshJWT := dbscProofJWT(t, privKey, challengeNonce, dbscSessionID)
	reqRefresh2 := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
	addCookies(reqRefresh2, cookies)
	reqRefresh2.Header.Set("Sec-Secure-Session-Id", `"`+dbscSessionID+`"`)
	reqRefresh2.Header.Set("Secure-Session-Response", sfString(refreshJWT))
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

func testDBSCSkippedRejected(t *testing.T) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, 5*time.Minute)

	_, dbscSessionID, cookies := completeDBSCRegistration(t, handler, privKey, nil)

	t.Run("different_session", func(t *testing.T) {
		req := newTestRequest(http.MethodGet, "/protected", nil)
		addCookies(req, cookies)
		req.Header.Set("Secure-Session-Skipped", `quota_exceeded;session_identifier="another-session"`)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("unrelated Secure-Session-Skipped: got %v want 200", rr.Code)
		}
	})

	t.Run("in_band", func(t *testing.T) {
		req := newTestRequest(http.MethodGet, "/protected", nil)
		addCookies(req, cookies)
		req.Header.Set("Secure-Session-Skipped", `unreachable;session_identifier="another-session", quota_exceeded;session_identifier="`+dbscSessionID+`"`)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("in-band with Secure-Session-Skipped: got %v want 401", rr.Code)
		}
	})

	t.Run("refresh", func(t *testing.T) {
		req := newTestRequest(http.MethodPost, "/dbsc/refresh", nil)
		addCookies(req, cookies)
		req.Header.Set("Sec-Secure-Session-Id", `"`+dbscSessionID+`"`)
		req.Header.Set("Secure-Session-Skipped", `unreachable;session_identifier="`+dbscSessionID+`"`)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("refresh with Secure-Session-Skipped: got %v want 401", rr.Code)
		}
	})
}

func testDBSCInBandChallenge(t *testing.T, refreshInterval time.Duration) {
	t.Helper()
	kv := &memoryKV{contents: make(map[string]kvItem)}
	_, handler, privKey, _ := setupDBSCHandler(t, kv, refreshInterval)

	_, dbscSessionID, cookies := completeDBSCRegistration(t, handler, privKey, nil)
	oldBoundCookie := findCookieByName(cookies, "__Host-session-id-bound")
	if oldBoundCookie == nil {
		t.Fatal("missing bound cookie after registration")
	}
	oldBoundValue := oldBoundCookie.Value

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
		t.Fatal("missing __Host-session-id cookie before in-band proof")
	}
	oldValue := oldSessionCookie.Value

	cookies = mergeCookies(cookies, extractCookies(rr2))

	refreshJWT := dbscProofJWT(t, privKey, challengeNonce, dbscSessionID)
	req3 := newTestRequest(http.MethodGet, "/protected", nil)
	addCookies(req3, cookies)
	req3.Header.Set("Secure-Session-Response", sfString(refreshJWT))
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("expected 200 after valid in-band challenge, got %v body: %s", rr3.Code, rr3.Body.String())
	}

	newSessionCookie := findCookieByName(extractCookies(rr3), "__Host-session-id")
	if newSessionCookie != nil && newSessionCookie.Value != oldValue && newSessionCookie.MaxAge != -1 {
		t.Fatal("in-band proof rotated the session cookie")
	}
	newBoundCookie := findCookieByName(extractCookies(rr3), "__Host-session-id-bound")
	if newBoundCookie == nil || newBoundCookie.MaxAge == -1 {
		t.Fatal("missing bound cookie after in-band proof")
	}
	if newBoundCookie.Value == oldBoundValue {
		t.Fatal("expected bound cookie to rotate after successful in-band challenge")
	}
}

func setupDBSCHandler(t *testing.T, kv KV, refreshInterval time.Duration) (*Manager[testSessionData], http.Handler, *ecdsa.PrivateKey, *http.Cookie) {
	t.Helper()
	opts := &KVManagerOpts[testSessionData]{
		IdleTimeout:          time.Hour,
		DBSCRefreshInterval:  refreshInterval,
		DBSCRegistrationPath: "/register",
		DBSCRefreshPath:      "/dbsc/refresh",
		DBSCOrigin:           "https://example.com",
	}
	mgr, err := NewKVManager[testSessionData](kv, opts)

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
			data := sess.Get()
			data.Bootstrap = "1"
			sess.Set(data)
			w.WriteHeader(http.StatusOK)
		default:
			if sess.Get().Bootstrap == "" {
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

	regJWT := dbscProofJWT(t, privKey, regChallenge, "")
	req1 := newTestRequest(http.MethodPost, "/register", nil)
	addCookies(req1, cookies)
	req1.Header.Set("Secure-Session-Response", sfString(regJWT))
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

func dbscProofJWT(t *testing.T, privKey *ecdsa.PrivateKey, jti, subject string) string {
	return dbscProofJWTWithIAT(t, privKey, jti, subject, time.Now())
}

func dbscProofJWTWithIAT(t *testing.T, privKey *ecdsa.PrivateKey, jti, subject string, iat time.Time) string {
	t.Helper()
	return dbscJOSEProofJWTAt(t, jose.ES256, privKey, jti, subject, iat)
}

func dbscJOSEProofJWTAt(t *testing.T, algorithm jose.SignatureAlgorithm, private any, challenge, subject string, issuedAt time.Time) string {
	t.Helper()
	opts := (&jose.SignerOptions{EmbedJWK: subject == ""}).WithType("dbsc+jwt")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: private}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := josejwt.Claims{ID: challenge}
	if !issuedAt.IsZero() {
		claims.IssuedAt = josejwt.NewNumericDate(issuedAt)
	}
	compact, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// dbscProofJWTJTIOOnly builds a current Editor's Draft proof with only jti.
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
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return req
}
