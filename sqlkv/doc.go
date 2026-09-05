// Package sqlkv provides a session store backed by database/sql.
//
// It supports Generic, MySQL, PostgreSQL, and SQLite dialects.
//
// Example schema:
//
//	CREATE TABLE web_sessions (
//		id TEXT PRIMARY KEY,
//		data BLOB NOT NULL,
//		expires_at TIMESTAMP NOT NULL
//	);
//	CREATE INDEX web_sessions_expires_at_idx ON web_sessions (expires_at);
//
// Usage with SQLite:
//
//	db, err := sql.Open("sqlite3", ":memory:")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create a new KV store
//	kv, err := sqlkv.New(db, &sqlkv.Opts{
//		Dialect: sqlkv.SQLite,
//		TableName: "my_sessions", // optional, defaults to "web_sessions"
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Create the table if it doesn't exist
//	if err := kv.CreateTable(context.Background()); err != nil {
//		log.Fatal(err)
//	}
//
//	// Configure a typed session manager to use this KV store
//	type SessionData struct {
//		UserID string `json:"user_id"`
//	}
//	manager, err := session.NewKVManager[SessionData](kv, nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Garbage collection:
//
//	// Run garbage collection once
//	deleted, err := kv.GC(context.Background())
//	if err != nil {
//		log.Printf("GC error: %v", err)
//	}
//	log.Printf("Deleted %d expired sessions", deleted)
//
//	// Or run garbage collection in the background at regular intervals
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	kv.RunGC(ctx, 10*time.Minute, log.New(os.Stdout, "GC: ", log.LstdFlags))
package sqlkv
