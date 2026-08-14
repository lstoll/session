# session

[![Go Reference](https://pkg.go.dev/badge/lds.li/session.svg)](https://pkg.go.dev/lds.li/session)

Typed HTTP sessions for Go. Session data normally lives in a server-side `KV`
store, with encrypted cookie sessions available when needed.

```sh
go get lds.li/session
```

```go
type SessionData struct {
	UserID string
}

sessions, err := session.NewKVManager[SessionData](session.NewMemoryKV(), nil)
if err != nil {
	log.Fatal(err)
}

mux := http.NewServeMux()
mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
	sessions.FromContext(r.Context()).Set(SessionData{UserID: "123"})
})
mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
	sessions.FromContext(r.Context()).Delete()
})

handler := sessions.Wrap(mux)
```

`NewMemoryKV` is useful for tests and single-process development. Production
deployments normally provide a shared `KV` implementation. The
[`sqlkv`](https://pkg.go.dev/lds.li/session/sqlkv) package provides one for
`database/sql`.

Cookie-backed sessions are available when self-contained storage is useful:

```go
aead, err := session.NewRotatingAESGCM(currentKey, previousKey)
if err != nil {
	log.Fatal(err)
}
cookieSessions, err := session.NewCookieManager[SessionData](aead, nil)
if err != nil {
	log.Fatal(err)
}
```

Cookie sessions are self-contained. The server can expire the browser's copy,
but it cannot revoke a copied cookie before its expiry. Load keys from a secret
store and keep the current key first. `NewRotatingAESGCM` and
`NewHMACSHA256Authenticator` both accept older keys for rotation.

Session changes must happen before the response is written or flushed. A
mutation after the response has committed panics, since it is too late to send
the updated cookie.

## DBSC

KV-backed sessions can be bound to a device using Device Bound Session
Credentials:

```go
sessions, err := session.NewKVManager[SessionData](store, &session.KVManagerOpts[SessionData]{
	DBSCRefreshInterval:  10 * time.Minute,
	DBSCOrigin:           "https://example.com",
	DBSCRegistrationPath: "/dbsc/register",
	DBSCRefreshPath:      "/dbsc/refresh",
})
```

The manager serves the registration and refresh endpoints and enforces proofs
on protected sessions. The implementation follows the current [W3C Editor's
Draft](https://w3c.github.io/webappsec-dbsc/) and has end-to-end coverage against
Chrome. DBSC is still experimental and its wire format may change.
