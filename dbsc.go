package session

import (
	"crypto/rand"
	"errors"
	"log/slog"
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
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
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

// dbscSessionSkipped reports whether Secure-Session-Skipped contains an
// sf-list member whose session_identifier parameter matches sessionID.
func dbscSessionSkipped(r *http.Request, sessionID string) bool {
	if sessionID == "" {
		return false
	}
	raw := strings.Join(r.Header.Values("Secure-Session-Skipped"), ",")
	members, ok := splitDBSCStructuredField(raw, ',')
	if !ok {
		return false
	}
	for _, member := range members {
		parts, ok := splitDBSCStructuredField(member, ';')
		if !ok || len(parts) == 0 || !isDBSCSFToken(strings.TrimSpace(parts[0])) {
			continue
		}
		for _, parameter := range parts[1:] {
			key, value, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if !found || key != "session_identifier" {
				continue
			}
			parsed, ok := parseSFString(strings.TrimSpace(value))
			if ok && parsed == sessionID {
				return true
			}
		}
	}
	return false
}

func splitDBSCStructuredField(value string, delimiter byte) ([]string, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, true
	}
	var parts []string
	start := 0
	inString := false
	escaped := false
	for i := range len(value) {
		c := value[i]
		if inString {
			switch {
			case escaped:
				if c != '\\' && c != '"' {
					return nil, false
				}
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			case c < 0x20 || c > 0x7e:
				return nil, false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c == delimiter {
			parts = append(parts, value[start:i])
			start = i + 1
		}
	}
	if inString || escaped {
		return nil, false
	}
	parts = append(parts, value[start:])
	return parts, true
}

func isDBSCSFToken(value string) bool {
	if value == "" || !isASCIIAlpha(value[0]) && value[0] != '*' {
		return false
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if !isASCIIAlpha(c) && (c < '0' || c > '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~:/", rune(c)) {
			return false
		}
	}
	return true
}

func isASCIIAlpha(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// dbscSameOriginRequest reports whether a DBSC registration or refresh POST
// should be accepted. Chrome's browser-process fetcher omits Sec-Fetch-*;
// only explicit cross-site or same-site values from a renderer are rejected.
func dbscSameOriginRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	default:
		return false
	}
}

func dbscFetchMetadata(r *http.Request) slog.Attr {
	return slog.Group("sec_fetch",
		"site", r.Header.Get("Sec-Fetch-Site"),
		"mode", r.Header.Get("Sec-Fetch-Mode"),
		"dest", r.Header.Get("Sec-Fetch-Dest"),
	)
}

// dbscShouldOfferRegistration reports whether to attach
// Secure-Session-Registration on this response. Cross-site and same-site
// requests are skipped. Same-origin and typed ("none") navigations offer.
func dbscShouldOfferRegistration(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	default:
		return false
	}
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

// dbscSessionIDHeader reads Sec-Secure-Session-Id from a request.
func dbscSessionIDHeader(r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.Header.Get("Sec-Secure-Session-Id"))
	if value, ok := parseSFString(raw); ok {
		return value, value != ""
	}
	// Chrome's current implementation sends the opaque session identifier
	// directly even though the Editor's Draft models this header as an
	// sf-string. The value is only compared with the server-issued identifier.
	if raw == "" || len(raw) > 128 || strings.ContainsAny(raw, " \t\r\n\";,") {
		return "", false
	}
	return raw, true
}
