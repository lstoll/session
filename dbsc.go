package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

const dbscClaimTyp = "dbsc+jwt"

// dbscProofMaxAge matches the server-side challenge TTL.
const dbscProofMaxAge = 5 * time.Minute

// dbscMaxRecentChallenges bounds persisted session growth while allowing a
// proof for a recently superseded challenge to arrive after a newer one.
const dbscMaxRecentChallenges = 4

type dbscChallenge struct {
	Value     string
	ExpiresAt time.Time
}

func issueDBSCChallenge[T any](sctx *Session[T], isRegister bool) (string, error) {
	challenge := rand.Text()
	if isRegister {
		sctx.sessdata.DBSCRegistrationChallenge = challenge
		sctx.state = sessionDirty
		return challenge, nil
	}
	if sctx.sessdata.DBSCSessionID == "" {
		return "", errors.New("cannot issue refresh challenge without DBSC session ID")
	}

	now := time.Now()
	recent := sctx.sessdata.DBSCChallenges[:0]
	for _, existing := range sctx.sessdata.DBSCChallenges {
		if existing.ExpiresAt.After(now) {
			recent = append(recent, existing)
		}
	}
	if len(recent) >= dbscMaxRecentChallenges {
		recent = recent[len(recent)-dbscMaxRecentChallenges+1:]
	}
	sctx.sessdata.DBSCChallenges = append(recent, dbscChallenge{
		Value:     challenge,
		ExpiresAt: now.Add(dbscProofMaxAge),
	})
	sctx.state = sessionDirty
	return challenge, nil
}

func verifyDBSCChallenge[T any](sctx *Session[T], challenge string, isRegister bool) error {
	if isRegister {
		if challenge == "" || sctx.sessdata.DBSCRegistrationChallenge != challenge {
			return errors.New("registration challenge mismatch or missing")
		}
		return nil
	}

	now := time.Now()
	for _, recent := range sctx.sessdata.DBSCChallenges {
		if recent.Value == challenge && recent.ExpiresAt.After(now) {
			return nil
		}
	}
	return errors.New("refresh challenge mismatch, missing, or expired")
}

func consumeDBSCChallenge[T any](sctx *Session[T], challenge string) {
	now := time.Now()
	recent := sctx.sessdata.DBSCChallenges[:0]
	for _, existing := range sctx.sessdata.DBSCChallenges {
		if existing.Value != challenge && existing.ExpiresAt.After(now) {
			recent = append(recent, existing)
		}
	}
	if len(recent) != len(sctx.sessdata.DBSCChallenges) {
		sctx.sessdata.DBSCChallenges = recent
		sctx.state = sessionDirty
	}
}

func dbscValidator() (*jwt.Validator, error) {
	return jwt.NewValidator(&jwt.ValidatorOpts{
		IgnoreIssuer:       true,
		IgnoreAudiences:    true,
		ExpectedTypeHeader: new(dbscClaimTyp),
		// DBSC proofs do not carry exp; freshness is enforced via jti/challenge
		// binding and, when present, iat (see validateDBSCProofFreshness). If a
		// client includes exp, Tink still rejects expired tokens.
		AllowMissingExpiration: true,
		ClockSkew:              time.Minute,
	})
}

// validateDBSCProofFreshness rejects proofs whose iat is too old. Chrome's DBSC
// proofs are typically jti-only; when iat is present we align with the W3C spec.
func validateDBSCProofFreshness(v *jwt.VerifiedJWT) error {
	if !v.HasIssuedAt() {
		return nil
	}
	iat, err := v.IssuedAt()
	if err != nil {
		return fmt.Errorf("iat claim: %w", err)
	}
	now := time.Now()
	if iat.After(now.Add(time.Minute)) {
		return errors.New("proof iat is in the future")
	}
	if now.Sub(iat) > dbscProofMaxAge+time.Minute {
		return errors.New("proof issued too long ago")
	}
	return nil
}

// stripDBSCProofToken returns the JWT string from a Secure-Session-Response
// value (an sf-string, which may appear quoted in some intermediaries).
func stripDBSCProofToken(s string) string {
	return stripSFString(s)
}

// stripSFString returns the inner string from an RFC 9651 sf-string value.
func stripSFString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// dbscSessionResponseHeader reads Secure-Session-Response (or legacy
// Sec-Session-Response) from a request.
func dbscSessionResponseHeader(r *http.Request) string {
	if v := r.Header.Get("Secure-Session-Response"); v != "" {
		return stripSFString(v)
	}
	return stripSFString(r.Header.Get("Sec-Session-Response"))
}

// parseDBSCRegistrationProof verifies a registration DBSC proof using the JWK
// embedded in the JWT header (§9.10) and returns the verified claims plus the
// public keyset handle Tink used for verification.
func parseDBSCRegistrationProof(ctx context.Context, compact string) (*jwt.VerifiedJWT, *keyset.Handle, error) {
	slog.DebugContext(ctx, "dbsc registration: parse proof", "jwt_len", len(compact))
	hdrB64, _, _, ok := parseToken(compact)
	if !ok {
		slog.DebugContext(ctx, "dbsc registration: invalid jwt shape")
		return nil, nil, errors.New("invalid token format")
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(hdrB64)
	if err != nil {
		slog.DebugContext(ctx, "dbsc registration: header base64 decode failed", "err", err)
		return nil, nil, fmt.Errorf("decoding jwt header: %w", err)
	}

	var hdr map[string]json.RawMessage
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		slog.DebugContext(ctx, "dbsc registration: header json failed", "err", err)
		return nil, nil, fmt.Errorf("unmarshalling header: %w", err)
	}
	jwkRaw, ok := hdr["jwk"]
	if !ok || len(jwkRaw) == 0 {
		slog.DebugContext(ctx, "dbsc registration: missing jwk in protected header")
		return nil, nil, errors.New("jwk field not found")
	}

	jwksJSON, err := dbscJWKSJSONFromRegistrationHeader(hdr, jwkRaw)
	if err != nil {
		slog.DebugContext(ctx, "dbsc registration: normalize jwk failed", "err", err)
		return nil, nil, err
	}
	ks, err := jwt.JWKSetToPublicKeysetHandle(jwksJSON)
	if err != nil {
		slog.DebugContext(ctx, "dbsc registration: JWKSetToPublicKeysetHandle failed", "err", err)
		return nil, nil, fmt.Errorf("converting jwks to public keyset: %w", err)
	}
	if ks.Len() != 1 {
		slog.DebugContext(ctx, "dbsc registration: jwks key count", "len", ks.Len())
		return nil, nil, errors.New("jwks must contain exactly one key")
	}

	verifier, err := jwt.NewVerifier(ks)
	if err != nil {
		slog.DebugContext(ctx, "dbsc registration: NewVerifier failed", "err", err)
		return nil, nil, fmt.Errorf("creating verifier: %w", err)
	}

	validator, err := dbscValidator()
	if err != nil {
		return nil, nil, err
	}

	verified, err := verifier.VerifyAndDecode(compact, validator)
	if err != nil {
		slog.DebugContext(ctx, "dbsc registration: VerifyAndDecode failed", "err", err)
		return nil, nil, fmt.Errorf("verifying and decoding: %w", err)
	}

	if err := validateDBSCProofFreshness(verified); err != nil {
		slog.DebugContext(ctx, "dbsc registration: proof freshness check failed", "err", err)
		return nil, nil, err
	}

	slog.DebugContext(ctx, "dbsc registration: jwt signature and claims ok")
	return verified, ks, nil
}

// dbscJWKSJSONFromRegistrationHeader builds a JWKS document for Tink from the
// JWT protected header. Chrome omits "alg" on the embedded JWK (§9.10 example);
// copy it from the JWT "alg" header when missing.
func dbscJWKSJSONFromRegistrationHeader(hdr map[string]json.RawMessage, jwkRaw json.RawMessage) ([]byte, error) {
	var jwk map[string]json.RawMessage
	if err := json.Unmarshal(jwkRaw, &jwk); err != nil {
		return nil, fmt.Errorf("unmarshalling jwk: %w", err)
	}
	if _, ok := jwk["alg"]; !ok {
		algRaw, ok := hdr["alg"]
		if !ok || len(algRaw) == 0 {
			return nil, errors.New("jwk and jwt header missing alg")
		}
		jwk["alg"] = algRaw
	}
	normalized, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("marshalling jwk: %w", err)
	}
	return json.Marshal(map[string]any{"keys": []json.RawMessage{normalized}})
}

// verifyDBSCRegistrationProofAndJWKS verifies a registration proof and returns
// the JWKS JSON produced by Tink for the verified public key (for later refresh verification).
func verifyDBSCRegistrationProofAndJWKS(ctx context.Context, compactToken, expectedChallenge string) ([]byte, error) {
	compact := stripDBSCProofToken(compactToken)
	if compact == "" {
		slog.DebugContext(ctx, "dbsc registration: empty proof after stripping")
		return nil, errors.New("empty proof token")
	}
	v, kh, err := parseDBSCRegistrationProof(ctx, compact)
	if err != nil {
		return nil, err
	}
	if !v.HasJWTID() {
		slog.DebugContext(ctx, "dbsc registration: no jti claim")
		return nil, errors.New("missing jti claim")
	}
	jti, err := v.JWTID()
	if err != nil {
		return nil, fmt.Errorf("jti claim: %w", err)
	}
	if jti != expectedChallenge {
		slog.DebugContext(ctx, "dbsc registration: jti mismatch",
			"jti_len", len(jti), "challenge_len", len(expectedChallenge))
		return nil, errors.New("jti does not match registration challenge")
	}
	jwks, err := jwt.JWKSetFromPublicKeysetHandle(kh)
	if err != nil {
		slog.DebugContext(ctx, "dbsc registration: JWKSetFromPublicKeysetHandle failed", "err", err)
		return nil, err
	}
	slog.DebugContext(ctx, "dbsc registration: proof ok", "jwks_len", len(jwks))
	return jwks, nil
}

// parseDBSCRefreshProof verifies a refresh DBSC proof using the stored public
// keyset (JWKS from registration).
func parseDBSCRefreshProof(compact string, handle *keyset.Handle) (*jwt.VerifiedJWT, error) {
	verifier, err := jwt.NewVerifier(handle)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	validator, err := dbscValidator()
	if err != nil {
		return nil, err
	}

	verified, err := verifier.VerifyAndDecode(compact, validator)
	if err != nil {
		return nil, fmt.Errorf("verifying and decoding: %w", err)
	}
	if err := validateDBSCProofFreshness(verified); err != nil {
		return nil, err
	}

	return verified, nil
}

// verifyDBSCResponse validates Secure-Session-Response for a refresh-style
// proof: signature with the bound key in jwksJSON, typ dbsc+jwt, and jti equal
// to the active challenge (§9.10).
func verifyDBSCResponse(raw string, jwksJSON []byte, challenge string) error {
	if challenge == "" {
		return errors.New("no active challenge")
	}
	token := stripDBSCProofToken(raw)
	if token == "" {
		return errors.New("empty proof token")
	}
	ks, err := jwt.JWKSetToPublicKeysetHandle(jwksJSON)
	if err != nil {
		return fmt.Errorf("jwks to public keyset: %w", err)
	}
	verified, err := parseDBSCRefreshProof(token, ks)
	if err != nil {
		return err
	}
	if !verified.HasJWTID() {
		return errors.New("missing jti claim")
	}
	jti, err := verified.JWTID()
	if err != nil {
		return fmt.Errorf("jti claim: %w", err)
	}
	if jti != challenge {
		return errors.New("jti does not match challenge")
	}
	return nil
}

// parseToken parses a JWT token string into its three parts: header, claims,
// and signature. Returns ok=false if the token format is invalid (must have
// exactly 2 periods).
func parseToken(s string) (header, claims, sig string, ok bool) {
	header, s, ok = strings.Cut(s, ".")
	if !ok { // no period found
		return "", "", "", false
	}
	claims, s, ok = strings.Cut(s, ".")
	if !ok { // only one period found
		return "", "", "", false
	}
	sig, _, ok = strings.Cut(s, ".")
	if ok { // three periods found (more than expected)
		return "", "", "", false
	}
	return header, claims, sig, true
}

func extractDBSCProofJTI(compactToken string) (string, error) {
	compact := stripDBSCProofToken(compactToken)
	_, claimsB64, _, ok := parseToken(compact)
	if !ok {
		return "", errors.New("invalid token format")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return "", fmt.Errorf("decoding jwt claims: %w", err)
	}
	var claims struct {
		Jti string `json:"jti"`
	}
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", fmt.Errorf("unmarshalling claims: %w", err)
	}
	return claims.Jti, nil
}
