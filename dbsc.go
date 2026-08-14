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
	return `(` + dbscproof.RegistrationAlgorithms() + `);path=` + sfString(path) + `;challenge=` + sfString(challenge)
}

func sfString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// parseSFString parses an RFC 9651 string and ignores any parameters, as the
// DBSC header definitions require.
func parseSFString(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '"' {
		return "", false
	}
	var value strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			rest := strings.TrimSpace(s[i+1:])
			return value.String(), rest == "" || strings.HasPrefix(rest, ";")
		case c == '\\':
			i++
			if i >= len(s) || (s[i] != '\\' && s[i] != '"') {
				return "", false
			}
			value.WriteByte(s[i])
		case c < 0x20 || c > 0x7e:
			return "", false
		default:
			value.WriteByte(c)
		}
	}
	return "", false
}

// dbscSessionResponseHeader reads Secure-Session-Response from a request.
func dbscSessionResponseHeader(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("Secure-Session-Response"))
	value, ok := parseSFString(raw)
	if !ok {
		// Chrome's current implementation sends the compact JWT directly even
		// though the Editor's Draft models this header as an sf-string.
		if strings.Count(raw, ".") == 2 && !strings.ContainsAny(raw, " \t\r\n") {
			return raw
		}
		return ""
	}
	return value
}
