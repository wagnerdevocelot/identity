package main

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ory/fosite"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}
	// create tables
	statements := []string{
		`CREATE TABLE clients (id TEXT PRIMARY KEY, secret TEXT, redirect_uris TEXT, scopes TEXT, is_public BOOLEAN)`,
		`CREATE TABLE tokens (signature TEXT PRIMARY KEY, client_id TEXT, token_type TEXT, data BLOB, revoked_at TIMESTAMP)`,
		`CREATE TABLE sessions (id TEXT PRIMARY KEY, session_type TEXT, data BLOB)`,
		`CREATE TABLE used_jtis (jti TEXT PRIMARY KEY, expires_at TIMESTAMP)`,
	}
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("failed to create table: %v", err)
		}
	}
	return db
}

func TestLegacyDBAdapterClientMethods(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	adapter := NewLegacyDBAdapter(db)

	// Create client
	client := &fosite.DefaultClient{ID: "c1", Secret: []byte("secret"), RedirectURIs: []string{"http://localhost"}}
	if err := adapter.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// Get client
	got, err := adapter.GetClient(ctx, "c1")
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}
	if got.GetID() != "c1" {
		t.Errorf("expected id c1 got %s", got.GetID())
	}

	// Update client
	client.RedirectURIs = []string{"http://127.0.0.1"}
	if err := adapter.UpdateClient(ctx, client); err != nil {
		t.Fatalf("UpdateClient failed: %v", err)
	}

	// Delete client
	if err := adapter.DeleteClient(ctx, "c1"); err != nil {
		t.Fatalf("DeleteClient failed: %v", err)
	}
	if _, err := adapter.GetClient(ctx, "c1"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("expected not found after delete got %v", err)
	}
}

func TestLegacyDBAdapterTokenMethods(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	adapter := NewLegacyDBAdapter(db)

	// create token
	payload := []byte("data")
	if err := adapter.CreateToken(ctx, "access_token", "sig1", "client", payload); err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}
	// get token
	got, err := adapter.GetToken(ctx, "access_token", "sig1")
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if string(got.([]byte)) != "data" {
		t.Errorf("unexpected token data: %v", got)
	}
	// revoke
	if err := adapter.RevokeToken(ctx, "access_token", "sig1"); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}
	// delete
	if err := adapter.DeleteToken(ctx, "access_token", "sig1"); err != nil {
		t.Fatalf("DeleteToken failed: %v", err)
	}
	if _, err := adapter.GetToken(ctx, "access_token", "sig1"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("expected not found after delete got %v", err)
	}
}

func TestLegacyDBAdapterSessionMethods(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	adapter := NewLegacyDBAdapter(db)

	data := []byte("session")
	if err := adapter.CreateSession(ctx, "openid", "s1", data); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	got, err := adapter.GetSession(ctx, "openid", "s1")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if string(got.([]byte)) != "session" {
		t.Errorf("unexpected session data: %v", got)
	}
	if err := adapter.DeleteSession(ctx, "openid", "s1"); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
	if _, err := adapter.GetSession(ctx, "openid", "s1"); !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("expected not found after delete got %v", err)
	}
}

func TestLegacyDBAdapterJWTMethods(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	adapter := NewLegacyDBAdapter(db)

	// validate new jti
	if err := adapter.ValidateJWT(ctx, "j1"); err != nil {
		t.Fatalf("ValidateJWT unexpected: %v", err)
	}
	// mark used
	if err := adapter.MarkJWTAsUsed(ctx, "j1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("MarkJWTAsUsed failed: %v", err)
	}
	// now validate should fail
	if err := adapter.ValidateJWT(ctx, "j1"); !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("expected JTIKnown after mark used got %v", err)
	}
}
