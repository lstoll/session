package sqlkv

import (
	"database/sql"
	"testing"
)

func TestNewRejectsInvalidTableName(t *testing.T) {
	for _, name := range []string{"sessions; DROP TABLE users", "schema.sessions", "quoted-name", "1sessions"} {
		if _, err := New(&sql.DB{}, &Opts{TableName: name}); err == nil {
			t.Fatalf("New accepted invalid table name %q", name)
		}
	}
}

func TestNewRejectsNilDatabase(t *testing.T) {
	if _, err := New(nil, nil); err == nil {
		t.Fatal("New accepted nil database")
	}
}
