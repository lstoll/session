// Package session provides typed HTTP sessions backed by encrypted cookies or
// a server-side key-value store.
//
// A Manager installs one Session per request. Get returns request-local *T
// data. Call Save after changing it. Save and Reset snapshot data immediately,
// so later changes require another Save. Flashes and idle refreshes preserve
// the last loaded or saved snapshot.
//
// Sessions are not safe for concurrent use. Mutating methods panic after the
// response is committed. T may be any non-pointer, non-interface type, and Get
// never returns nil.
//
// Cookie-backed sessions cannot revoke previously issued cookie values. Use a
// KV-backed manager when logout or session renewal must invalidate an old
// credential server-side.
package session
