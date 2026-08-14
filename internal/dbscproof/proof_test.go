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
	for _, tt := range []struct {
		name      string
		algorithm jose.SignatureAlgorithm
		private   any
	}{
		{name: "ES256", algorithm: jose.ES256, private: newECDSAKey(t)},
		{name: "RS256", algorithm: jose.RS256, private: newRSAKey(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			registration := signProof(t, tt.algorithm, tt.private, "registration", true, time.Time{})
			result, err := VerifyRegistration(registration)
			if err != nil {
				t.Fatal(err)
			}
			if result.Key.Algorithm != string(tt.algorithm) || result.Challenge != "registration" {
				t.Fatalf("registration = %#v", result)
			}
			var stored jose.JSONWebKey
			if err := json.Unmarshal(result.Key.JWK, &stored); err != nil {
				t.Fatal(err)
			}
			if !stored.IsPublic() {
				t.Fatal("stored registration key contains private material")
			}

			refresh := signProof(t, tt.algorithm, tt.private, "refresh", false, time.Time{})
			challenge, err := VerifyRefresh(refresh, result.Key)
			if err != nil || challenge != "refresh" {
				t.Fatalf("refresh = %q, %v", challenge, err)
			}
		})
	}
}

func TestVerifyRegistrationRejectsInvalidProofs(t *testing.T) {
	private := newECDSAKey(t)
	for _, tt := range []struct {
		name     string
		typ      string
		jti      string
		embedJWK bool
		iat      time.Time
	}{
		{name: "missing type", jti: "challenge", embedJWK: true},
		{name: "wrong type", typ: "JWT", jti: "challenge", embedJWK: true},
		{name: "missing jwk", typ: Type, jti: "challenge"},
		{name: "missing jti", typ: Type, embedJWK: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proof := signProofWithType(t, jose.ES256, private, tt.typ, tt.jti, tt.embedJWK, tt.iat)
			if _, err := VerifyRegistration(proof); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}

func TestVerifyRefreshRejectsInvalidProofs(t *testing.T) {
	private := newECDSAKey(t)
	registration, err := VerifyRegistration(signProof(t, jose.ES256, private, "registration", true, time.Time{}))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyRefresh(signProof(t, jose.ES256, private, "refresh", true, time.Time{}), registration.Key); err == nil {
		t.Fatal("refresh proof with embedded JWK accepted")
	}
	if _, err := VerifyRefresh(signProof(t, jose.ES256, newECDSAKey(t), "refresh", false, time.Time{}), registration.Key); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong signature error = %v", err)
	}
	if _, err := VerifyRefresh("not-a-jwt", registration.Key); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("malformed token error = %v", err)
	}
	rsProof := signProof(t, jose.RS256, newRSAKey(t), "refresh", false, time.Time{})
	if _, err := VerifyRefresh(rsProof, registration.Key); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("algorithm switch error = %v", err)
	}
}

func TestVerifyRegistrationAllowsUnspecifiedOptionalClaims(t *testing.T) {
	private := newECDSAKey(t)
	proof := signProof(t, jose.ES256, private, "registration", true, time.Now().Add(-24*time.Hour))
	if _, err := VerifyRegistration(proof); err != nil {
		t.Fatalf("optional iat affected DBSC proof validation: %v", err)
	}
}

func TestValidateRSAKeyPolicy(t *testing.T) {
	private := newRSAKey(t)
	for _, key := range []*rsa.PublicKey{
		{N: private.N, E: 1},
		{N: private.N, E: 65536},
		{N: new(big.Int).Lsh(big.NewInt(1), minRSABits-2), E: rsaExponent},
	} {
		if err := validateKey(&jose.JSONWebKey{Key: key}, string(jose.RS256)); err == nil {
			t.Fatal("unsafe RSA key accepted")
		}
	}
}

func signProof(t *testing.T, algorithm jose.SignatureAlgorithm, private any, challenge string, embedJWK bool, issuedAt time.Time) string {
	t.Helper()
	return signProofWithType(t, algorithm, private, Type, challenge, embedJWK, issuedAt)
}

func signProofWithType(t *testing.T, algorithm jose.SignatureAlgorithm, private any, typ, challenge string, embedJWK bool, issuedAt time.Time) string {
	t.Helper()
	opts := &jose.SignerOptions{EmbedJWK: embedJWK}
	if typ != "" {
		opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: private}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{ID: challenge}
	if !issuedAt.IsZero() {
		claims.IssuedAt = jwt.NewNumericDate(issuedAt)
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
