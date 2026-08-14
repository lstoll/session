package dbscproof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	Type           = "dbsc+jwt"
	proofMaxAge    = 5 * time.Minute
	clockSkew      = time.Minute
	maxCompactSize = 16 << 10
	minRSABits     = 2048
	maxRSABits     = 8192
	rsaExponent    = 65537
)

var registrationAlgorithms = func() string {
	algorithms := supportedAlgorithms()
	names := make([]string, len(algorithms))
	for i, algorithm := range algorithms {
		names[i] = string(algorithm)
	}
	return strings.Join(names, " ")
}()

var (
	// ErrMalformedProof identifies proofs that cannot be parsed or whose JOSE
	// headers do not match the DBSC proof format.
	ErrMalformedProof = errors.New("malformed DBSC proof")
	// ErrInvalidSignature identifies proofs not signed by the expected key.
	ErrInvalidSignature = errors.New("invalid DBSC proof signature")
	// ErrInvalidClaims identifies signed proofs with invalid JWT claims.
	ErrInvalidClaims = errors.New("invalid DBSC proof claims")
	// ErrInvalidKey identifies unsupported or unsafe registered public keys.
	ErrInvalidKey = errors.New("invalid DBSC public key")
)

func supportedAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256, jose.RS256}
}

// RegistrationAlgorithms returns the algorithms to advertise, in preference
// order, in Secure-Session-Registration.
func RegistrationAlgorithms() string {
	return registrationAlgorithms
}

// RegisteredKey is the verified public key material established during registration.
// JWK contains one canonical public JWK, not a JWK set.
type RegisteredKey struct {
	Algorithm string
	JWK       []byte
}

// Registration is the verified result of a registration proof.
type Registration struct {
	Key       RegisteredKey
	Challenge string
}

// VerifyRegistration verifies a registration proof using its protected JWK
// header and returns canonical key material for later refresh proofs.
func VerifyRegistration(compact string, now time.Time) (Registration, error) {
	parsed, header, err := parse(compact, supportedAlgorithms())
	if err != nil {
		return Registration{}, err
	}
	if header.JSONWebKey == nil {
		return Registration{}, fmt.Errorf("%w: registration proof is missing protected jwk", ErrMalformedProof)
	}

	jwk := header.JSONWebKey
	algorithm := header.Algorithm
	if err := validateKey(jwk, algorithm); err != nil {
		return Registration{}, fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	var claims jwt.Claims
	if err := parsed.Claims(jwk.Key, &claims); err != nil {
		return Registration{}, fmt.Errorf("%w: verifying registration proof: %v", ErrInvalidSignature, err)
	}
	challenge, err := validateClaims(claims, now)
	if err != nil {
		return Registration{}, err
	}

	// Persist only the public key material needed for refresh verification.
	publicJWK := jose.JSONWebKey{Key: jwk.Key}
	encoded, err := json.Marshal(publicJWK)
	if err != nil {
		return Registration{}, fmt.Errorf("marshalling public jwk: %w", err)
	}
	return Registration{
		Key: RegisteredKey{
			Algorithm: algorithm,
			JWK:       encoded,
		},
		Challenge: challenge,
	}, nil
}

// VerifyRefresh verifies a refresh proof with the key established during
// registration.
func VerifyRefresh(compact string, key RegisteredKey, now time.Time) (string, error) {
	algorithm := jose.SignatureAlgorithm(key.Algorithm)
	if algorithm != jose.ES256 && algorithm != jose.RS256 {
		return "", fmt.Errorf("%w: unsupported registered algorithm %q", ErrInvalidKey, key.Algorithm)
	}
	parsed, header, err := parse(compact, []jose.SignatureAlgorithm{algorithm})
	if err != nil {
		return "", err
	}
	if header.JSONWebKey != nil {
		return "", fmt.Errorf("%w: refresh proof must not contain jwk", ErrMalformedProof)
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(key.JWK, &jwk); err != nil {
		return "", fmt.Errorf("%w: unmarshalling registered jwk: %v", ErrInvalidKey, err)
	}
	if err := validateKey(&jwk, key.Algorithm); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	var claims jwt.Claims
	if err := parsed.Claims(jwk.Key, &claims); err != nil {
		return "", fmt.Errorf("%w: verifying refresh proof: %v", ErrInvalidSignature, err)
	}
	return validateClaims(claims, now)
}

func parse(compact string, algorithms []jose.SignatureAlgorithm) (*jwt.JSONWebToken, jose.Header, error) {
	if len(compact) == 0 || len(compact) > maxCompactSize {
		return nil, jose.Header{}, fmt.Errorf("%w: invalid proof size", ErrMalformedProof)
	}
	parsed, err := jwt.ParseSigned(compact, algorithms)
	if err != nil {
		return nil, jose.Header{}, fmt.Errorf("%w: parsing proof: %v", ErrMalformedProof, err)
	}
	if len(parsed.Headers) != 1 {
		return nil, jose.Header{}, fmt.Errorf("%w: proof must contain exactly one signature", ErrMalformedProof)
	}
	header := parsed.Headers[0]
	typ, ok := header.ExtraHeaders[jose.HeaderType].(string)
	if !ok || typ != Type {
		return nil, jose.Header{}, fmt.Errorf("%w: unexpected proof type %q", ErrMalformedProof, typ)
	}
	return parsed, header, nil
}

func validateKey(jwk *jose.JSONWebKey, algorithm string) error {
	if !jwk.Valid() || !jwk.IsPublic() {
		return errors.New("jwk must contain a valid public key")
	}
	if jwk.Algorithm != "" && jwk.Algorithm != algorithm {
		return errors.New("jwk algorithm does not match proof algorithm")
	}

	switch key := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		if algorithm != string(jose.ES256) || key.Curve != elliptic.P256() {
			return errors.New("ES256 requires a P-256 public key")
		}
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		if algorithm != string(jose.RS256) || bits < minRSABits || bits > maxRSABits {
			return fmt.Errorf("RS256 requires an RSA public key between %d and %d bits", minRSABits, maxRSABits)
		}
		if key.E != rsaExponent {
			return fmt.Errorf("RS256 requires RSA public exponent %d", rsaExponent)
		}
	default:
		return fmt.Errorf("unsupported public key type %T", jwk.Key)
	}
	return nil
}

func validateClaims(claims jwt.Claims, now time.Time) (string, error) {
	if claims.ID == "" {
		return "", fmt.Errorf("%w: missing jti claim", ErrInvalidClaims)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Time: now}, clockSkew); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	}
	if claims.IssuedAt != nil && now.Sub(claims.IssuedAt.Time()) > proofMaxAge+clockSkew {
		return "", fmt.Errorf("%w: proof issued too long ago", ErrInvalidClaims)
	}
	return claims.ID, nil
}
