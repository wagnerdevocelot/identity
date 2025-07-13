package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// LegacyDBAdapter implements StorageInterface using a legacy SQL database.
// It demonstrates how one could adapt a pre-existing schema to the
// StorageInterface expected by the OAuth2 service.
//
// This adapter is intentionally simple and does not rely on any ORM. It uses
// database/sql directly so that it can map legacy tables to the fosite models.
type LegacyDBAdapter struct {
	DB *sql.DB
}

// NewLegacyDBAdapter returns a new adapter instance using the given sql.DB.
func NewLegacyDBAdapter(db *sql.DB) *LegacyDBAdapter {
	return &LegacyDBAdapter{DB: db}
}

// ---- Entity Mapping Structures ----
// These structs represent how data is stored in the legacy database.
// They are converted to/from fosite models when interacting with the service.

type legacyClient struct {
	ID           string
	Secret       string
	RedirectURIs string // comma separated
	Scopes       string // comma separated
	IsPublic     bool
}

func (lc legacyClient) toFosite() fosite.Client {
	return &fosite.DefaultClient{
		ID:           lc.ID,
		Secret:       []byte(lc.Secret),
		RedirectURIs: splitAndTrim(lc.RedirectURIs),
		Scopes:       fosite.Arguments(splitAndTrim(lc.Scopes)),
		Public:       lc.IsPublic,
	}
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	var res []string
	for _, part := range strings.Split(s, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

// ---- StorageInterface Implementation ----

func (a *LegacyDBAdapter) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	row := a.DB.QueryRowContext(ctx, `SELECT id, secret, redirect_uris, scopes, is_public FROM clients WHERE id = ?`, id)
	var lc legacyClient
	if err := row.Scan(&lc.ID, &lc.Secret, &lc.RedirectURIs, &lc.Scopes, &lc.IsPublic); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("client not found: %w", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("db query failed: %w", err)
	}
	return lc.toFosite(), nil
}

func (a *LegacyDBAdapter) CreateClient(ctx context.Context, client fosite.Client) error {
	c, ok := client.(*fosite.DefaultClient)
	if !ok {
		return fmt.Errorf("unsupported client type %T", client)
	}
	_, err := a.DB.ExecContext(ctx,
		`INSERT INTO clients (id, secret, redirect_uris, scopes, is_public) VALUES (?, ?, ?, ?, ?)`,
		c.ID,
		string(c.Secret),
		strings.Join(c.RedirectURIs, ","),
		strings.Join(c.Scopes, ","),
		c.Public,
	)
	if err != nil {
		return fmt.Errorf("failed to insert client: %w", err)
	}
	return nil
}

func (a *LegacyDBAdapter) UpdateClient(ctx context.Context, client fosite.Client) error {
	c, ok := client.(*fosite.DefaultClient)
	if !ok {
		return fmt.Errorf("unsupported client type %T", client)
	}
	_, err := a.DB.ExecContext(ctx,
		`UPDATE clients SET secret=?, redirect_uris=?, scopes=?, is_public=? WHERE id=?`,
		string(c.Secret),
		strings.Join(c.RedirectURIs, ","),
		strings.Join(c.Scopes, ","),
		c.Public,
		c.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}
	return nil
}

func (a *LegacyDBAdapter) DeleteClient(ctx context.Context, id string) error {
	_, err := a.DB.ExecContext(ctx, `DELETE FROM clients WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

// Token operations in the legacy DB use a generic tokens table. Each token type
// is mapped by the token_type column. Only minimal fields required by fosite are
// stored here.
type legacyToken struct {
	Signature string
	ClientID  string
	TokenType string
	Data      []byte
}

func (a *LegacyDBAdapter) CreateToken(ctx context.Context, tokenType, signature, clientID string, data interface{}) error {
	// data is expected to be encoded outside. We assume caller provides []byte.
	b, ok := data.([]byte)
	if !ok {
		return fmt.Errorf("invalid token payload type %T", data)
	}
	_, err := a.DB.ExecContext(ctx,
		`INSERT INTO tokens (signature, client_id, token_type, data) VALUES (?, ?, ?, ?)`,
		signature, clientID, tokenType, b)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}
	return nil
}

func (a *LegacyDBAdapter) GetToken(ctx context.Context, tokenType, signature string) (interface{}, error) {
	row := a.DB.QueryRowContext(ctx, `SELECT data FROM tokens WHERE signature=? AND token_type=?`, signature, tokenType)
	var data []byte
	if err := row.Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: token not found", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("db query failed: %w", err)
	}
	return data, nil
}

func (a *LegacyDBAdapter) DeleteToken(ctx context.Context, tokenType, signature string) error {
	_, err := a.DB.ExecContext(ctx, `DELETE FROM tokens WHERE signature=? AND token_type=?`, signature, tokenType)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}
	return nil
}

func (a *LegacyDBAdapter) RevokeToken(ctx context.Context, tokenType, signature string) error {
	// Mark token as revoked using a revoked_at column; create the column if not present.
	_, err := a.DB.ExecContext(ctx,
		`UPDATE tokens SET revoked_at=? WHERE signature=? AND token_type=?`,
		time.Now().UTC(), signature, tokenType)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	return nil
}

// Session operations map directly to a sessions table. The "session_type"
// column differentiates between openid, pkce, etc.
func (a *LegacyDBAdapter) CreateSession(ctx context.Context, sessionType, id string, data interface{}) error {
	b, ok := data.([]byte)
	if !ok {
		return fmt.Errorf("invalid session payload type %T", data)
	}
	_, err := a.DB.ExecContext(ctx,
		`INSERT INTO sessions (id, session_type, data) VALUES (?, ?, ?)`,
		id, sessionType, b,
	)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

func (a *LegacyDBAdapter) GetSession(ctx context.Context, sessionType, id string) (interface{}, error) {
	row := a.DB.QueryRowContext(ctx, `SELECT data FROM sessions WHERE id=? AND session_type=?`, id, sessionType)
	var data []byte
	if err := row.Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: session not found", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("db query failed: %w", err)
	}
	return data, nil
}

func (a *LegacyDBAdapter) DeleteSession(ctx context.Context, sessionType, id string) error {
	_, err := a.DB.ExecContext(ctx, `DELETE FROM sessions WHERE id=? AND session_type=?`, id, sessionType)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

func (a *LegacyDBAdapter) ValidateJWT(ctx context.Context, jti string) error {
	row := a.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM used_jtis WHERE jti=?)`, jti)
	var exists bool
	if err := row.Scan(&exists); err != nil {
		return fmt.Errorf("db query failed: %w", err)
	}
	if exists {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (a *LegacyDBAdapter) MarkJWTAsUsed(ctx context.Context, jti string, exp time.Time) error {
	_, err := a.DB.ExecContext(ctx,
		`INSERT INTO used_jtis (jti, expires_at) VALUES (?, ?)`, jti, exp.UTC())
	if err != nil {
		return fmt.Errorf("failed to mark jti used: %w", err)
	}
	return nil
}

// Ensure interface compliance
var _ StorageInterface = (*LegacyDBAdapter)(nil)
