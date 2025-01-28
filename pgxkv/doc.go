// Package pgxkv provides a postgres-backed session store using the pgx driver
//
// Example Schema:
//	CREATE TABLE web_sessions (
//		id TEXT PRIMARY KEY,
//		data JSONB NOT NULL, -- if JSON serialized, if proto then bytea
//		expires_at TIMESTAMPTZ NOT NULL
//	);

package pgxkv
