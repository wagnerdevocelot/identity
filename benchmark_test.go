package main

import (
	"context"
	"database/sql"
	"strconv"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ory/fosite"
)

func BenchmarkLoggingAdapterCreateToken(b *testing.B) {
	adapter := NewLoggingAdapter(NewInMemoryStore())
	req := &fosite.Request{}
	for i := 0; i < b.N; i++ {
		adapter.CreateToken(context.Background(), "access_token", "sig"+strconv.Itoa(i), "c1", req)
	}
}

func BenchmarkLegacyDBCreateToken(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE tokens (signature TEXT PRIMARY KEY, client_id TEXT, token_type TEXT, data BLOB, revoked_at TIMESTAMP)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			b.Fatal(err)
		}
	}
	adapter := NewLegacyDBAdapter(db)
	req := []byte("data")
	for i := 0; i < b.N; i++ {
		adapter.CreateToken(context.Background(), "access_token", "sig"+strconv.Itoa(i), "c1", req)
	}
}
