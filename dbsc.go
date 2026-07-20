package session

import (
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"time"

	"lds.li/session/internal/dbscproof"
)

const dbscChallengeTTL = 5 * time.Minute

// dbscMaxRecentChallenges bounds persisted session growth while allowing a
// proof for a recently superseded challenge to arrive after a newer one.
const dbscMaxRecentChallenges = 4

type dbscChallenge struct {
	Value     string
	ExpiresAt time.Time
}

func registeredDBSCKey[T any](sctx *Session[T]) dbscproof.RegisteredKey {
	return dbscproof.RegisteredKey{
		Algorithm: sctx.sessdata.DBSCAlgorithm,
		JWK:       sctx.sessdata.DBSCPublicJWK,
	}
}

func issueDBSCRegistrationChallenge[T any](sctx *Session[T], now time.Time) string {
	challenge := rand.Text()
	sctx.sessdata.DBSCRegistrationChallenge = dbscChallenge{
		Value:     challenge,
		ExpiresAt: now.Add(dbscChallengeTTL),
	}
	sctx.state = sessionDirty
	return challenge
}

func issueDBSCRefreshChallenge[T any](sctx *Session[T], now time.Time) (string, error) {
	if sctx.sessdata.DBSCSessionID == "" {
		return "", errors.New("cannot issue refresh challenge without DBSC session ID")
	}

	challenge := rand.Text()
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
		ExpiresAt: now.Add(dbscChallengeTTL),
	})
	sctx.state = sessionDirty
	return challenge, nil
}

func verifyDBSCRegistrationChallenge[T any](sctx *Session[T], challenge string, now time.Time) error {
	pending := sctx.sessdata.DBSCRegistrationChallenge
	if challenge == "" || pending.Value != challenge || !pending.ExpiresAt.After(now) {
		return errors.New("registration challenge mismatch, missing, or expired")
	}
	return nil
}

func verifyDBSCRefreshChallenge[T any](sctx *Session[T], challenge string, now time.Time) error {
	for _, recent := range sctx.sessdata.DBSCChallenges {
		if recent.Value == challenge && recent.ExpiresAt.After(now) {
			return nil
		}
	}
	return errors.New("refresh challenge mismatch, missing, or expired")
}

func consumeDBSCRefreshChallenge[T any](sctx *Session[T], challenge string, now time.Time) {
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

func hasPendingDBSCRegistrationChallenge[T any](sctx *Session[T], now time.Time) bool {
	pending := sctx.sessdata.DBSCRegistrationChallenge
	return pending.Value != "" && pending.ExpiresAt.After(now)
}

func dbscRegistrationHeader(path, challenge string) string {
	return `(` + dbscproof.RegistrationAlgorithms() + `);path="` + path + `";challenge="` + challenge + `"`
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
