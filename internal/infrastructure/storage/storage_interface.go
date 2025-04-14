// Package storage contém as implementações de armazenamento de dados.
package storage

import (
	"context"
	"time"

	"github.com/ory/fosite"
)

// StorageInterface define um contrato genérico para todas as implementações de armazenamento,
// fornecendo um conjunto comum de métodos para operações CRUD em diferentes entidades.
type StorageInterface interface {
	// Operações de cliente
	GetClient(ctx context.Context, id string) (fosite.Client, error)
	CreateClient(ctx context.Context, client fosite.Client) error
	UpdateClient(ctx context.Context, client fosite.Client) error
	DeleteClient(ctx context.Context, id string) error

	// Operações de token
	CreateToken(ctx context.Context, tokenType string, signature string, clientID string, data interface{}) error
	GetToken(ctx context.Context, tokenType string, signature string) (interface{}, error)
	DeleteToken(ctx context.Context, tokenType string, signature string) error
	RevokeToken(ctx context.Context, tokenType string, signature string) error

	// Operações de sessão
	CreateSession(ctx context.Context, sessionType string, id string, data interface{}) error
	GetSession(ctx context.Context, sessionType string, id string) (interface{}, error)
	DeleteSession(ctx context.Context, sessionType string, id string) error

	// Operações JWT
	ValidateJWT(ctx context.Context, jti string) error
	MarkJWTAsUsed(ctx context.Context, jti string, exp time.Time) error
}
