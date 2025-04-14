// Package service contém interfaces para serviços do domínio.
package service

import (
	"context"
	"time"

	"identity-go/internal/domain/entity"
)

// AuthenticationService define as operações relacionadas à autenticação.
type AuthenticationService interface {
	// Authenticate verifica as credenciais do usuário e retorna o usuário se autenticado com sucesso.
	Authenticate(ctx context.Context, username, password string) (*entity.User, error)

	// GenerateToken gera um token de acesso para o usuário.
	GenerateToken(ctx context.Context, user *entity.User, scopes []string, clientID string) (string, time.Time, error)

	// ValidateToken verifica se um token é válido e retorna o usuário associado.
	ValidateToken(ctx context.Context, token string) (*entity.User, error)

	// HashPassword gera um hash seguro para a senha fornecida.
	HashPassword(password string) (string, error)

	// VerifyPassword verifica se a senha corresponde ao hash armazenado.
	VerifyPassword(hashedPassword, password string) error

	// RevokeToken revoga um token específico.
	RevokeToken(ctx context.Context, token string) error
}

// AuthorizationService define as operações relacionadas à autorização.
type AuthorizationService interface {
	// CheckPermission verifica se um usuário tem permissão para acessar um recurso.
	CheckPermission(ctx context.Context, userID, resource, action string) (bool, error)

	// CreateConsent cria um consentimento para determinados escopos.
	CreateConsent(ctx context.Context, userID string, clientID string, scopes []string) error

	// GetUserConsents obtém todos os consentimentos concedidos por um usuário.
	GetUserConsents(ctx context.Context, userID string) ([]Consent, error)

	// RevokeConsent revoga um consentimento específico.
	RevokeConsent(ctx context.Context, userID, clientID string) error
}

// Consent representa um consentimento dado por um usuário a um cliente para acesso a escopos.
type Consent struct {
	UserID    string
	ClientID  string
	Scopes    []string
	GrantedAt time.Time
	ExpiresAt time.Time
}
