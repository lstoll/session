package dbscproof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestVerifyRegistrationAndRefresh(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		algorithm jose.SignatureAlgorithm
		private   any
	}{
		{
			name:      "ES256",
			algorithm: jose.ES256,
			private:   newECDSAKey(t),
		},
		{
			name:      "RS256",
			algorithm: jose.RS256,
			private:   newRSAKey(t),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registration := signProof(t, tt.algorithm, tt.private, "registration", true)
			registrationResult, err := VerifyRegistration(registration, now)
			if err != nil {
				t.Fatal(err)
			}
			if registrationResult.Key.Algorithm != string(tt.algorithm) || len(registrationResult.Key.JWK) == 0 {
				t.Fatalf("registered key = %#v", registrationResult.Key)
			}
			if registrationResult.Challenge != "registration" {
				t.Fatalf("registration challenge = %q", registrationResult.Challenge)
			}
			var stored jose.JSONWebKey
			if err := json.Unmarshal(registrationResult.Key.JWK, &stored); err != nil {
				t.Fatal(err)
			}
			if !stored.IsPublic() {
				t.Fatal("stored registration key contains private material")
			}

			refresh := signProof(t, tt.algorithm, tt.private, "refresh", false)
			challenge, err := VerifyRefresh(refresh, registrationResult.Key, now)
			if err != nil {
				t.Fatal(err)
			}
			if challenge != "refresh" {
				t.Fatalf("refresh challenge = %q", challenge)
			}
		})
	}
}

func TestVerifyRefreshRejectsEmbeddedJWK(t *testing.T) {
	private := newECDSAKey(t)
	registration := signProof(t, jose.ES256, private, "registration", true)
	registrationResult, err := VerifyRegistration(registration, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	refresh := signProof(t, jose.ES256, private, "refresh", true)
	if _, err := VerifyRefresh(refresh, registrationResult.Key, time.Now()); err == nil {
		t.Fatal("refresh proof with embedded jwk was accepted")
	}
}

func TestVerifyRefreshDoesNotReturnUnverifiedChallenge(t *testing.T) {
	registered := newECDSAKey(t)
	registration := signProof(t, jose.ES256, registered, "registration", true)
	registrationResult, err := VerifyRegistration(registration, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	attacker := newECDSAKey(t)
	proof := signProof(t, jose.ES256, attacker, "attacker-challenge", false)
	challenge, err := VerifyRefresh(proof, registrationResult.Key, time.Now())
	if err == nil {
		t.Fatal("proof signed by an unregistered key was accepted")
	}
	if challenge != "" {
		t.Fatalf("returned unverified challenge %q", challenge)
	}
}

func TestValidateRSAKeyPolicy(t *testing.T) {
	private := newRSAKey(t)
	tests := []struct {
		name string
		key  *rsa.PublicKey
	}{
		{name: "unsafe exponent", key: &rsa.PublicKey{N: private.N, E: 1}},
		{name: "even exponent", key: &rsa.PublicKey{N: private.N, E: 65536}},
		{name: "small modulus", key: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), minRSABits-2), E: rsaExponent}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateKey(&jose.JSONWebKey{Key: tt.key}, string(jose.RS256)); err == nil {
				t.Fatal("unsafe RSA key accepted")
			}
		})
	}
}

func TestVerifyRegistrationRejectsInvalidHeadersAndClaims(t *testing.T) {
	private := newECDSAKey(t)
	now := time.Now()
	tests := []struct {
		name   string
		typ    string
		claims jwt.Claims
	}{
		{name: "missing type", claims: jwt.Claims{ID: "challenge"}},
		{name: "wrong type", typ: "JWT", claims: jwt.Claims{ID: "challenge"}},
		{name: "missing jti", typ: Type, claims: jwt.Claims{}},
		{name: "expired", typ: Type, claims: jwt.Claims{ID: "challenge", Expiry: jwt.NewNumericDate(now.Add(-2 * clockSkew))}},
		{name: "future iat", typ: Type, claims: jwt.Claims{ID: "challenge", IssuedAt: jwt.NewNumericDate(now.Add(2 * clockSkew))}},
		{name: "stale iat", typ: Type, claims: jwt.Claims{ID: "challenge", IssuedAt: jwt.NewNumericDate(now.Add(-proofMaxAge - 2*clockSkew))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := signClaims(t, jose.ES256, private, tt.typ, tt.claims, true)
			if _, err := VerifyRegistration(proof, now); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}

func TestVerifyRefreshRejectsAlgorithmSwitch(t *testing.T) {
	esPrivate := newECDSAKey(t)
	registration, err := VerifyRegistration(signProof(t, jose.ES256, esPrivate, "registration", true), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rsProof := signProof(t, jose.RS256, newRSAKey(t), "refresh", false)
	if _, err := VerifyRefresh(rsProof, registration.Key, time.Now()); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("algorithm switch error = %v, want malformed proof", err)
	}
}

func TestVerifyRefreshErrorCategories(t *testing.T) {
	private := newECDSAKey(t)
	registration, err := VerifyRegistration(signProof(t, jose.ES256, private, "registration", true), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyRefresh("not-a-jwt", registration.Key, time.Now()); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("malformed token error = %v", err)
	}
	attackerProof := signProof(t, jose.ES256, newECDSAKey(t), "refresh", false)
	if _, err := VerifyRefresh(attackerProof, registration.Key, time.Now()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("bad signature error = %v", err)
	}
	missingJTI := signClaims(t, jose.ES256, private, Type, jwt.Claims{}, false)
	if _, err := VerifyRefresh(missingJTI, registration.Key, time.Now()); !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("invalid claims error = %v", err)
	}
}

func signProof(t *testing.T, algorithm jose.SignatureAlgorithm, private any, challenge string, embedJWK bool) string {
	t.Helper()
	return signClaims(t, algorithm, private, Type, jwt.Claims{ID: challenge}, embedJWK)
}

func signClaims(t *testing.T, algorithm jose.SignatureAlgorithm, private any, typ string, claims jwt.Claims, embedJWK bool) string {
	t.Helper()
	opts := &jose.SignerOptions{EmbedJWK: embedJWK}
	if typ != "" {
		opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: private}, opts)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, minRSABits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
