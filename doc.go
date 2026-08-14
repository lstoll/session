// Package session provides typed HTTP sessions backed by encrypted cookies or
// a server-side key-value store.
//
// A Manager installs a request-scoped Session in the request context. Session
// mutations are saved before the response is committed; mutating after a
// Write, WriteHeader, or Flush panics.
//
// Cookie-backed sessions cannot revoke previously issued cookie values. Use a
// KV-backed manager when logout or session renewal must invalidate an old
// credential server-side.
package session
