// Package auth contém os casos de uso relacionados à autenticação.
package auth

import (
	"context"
	"errors"
	"time"

	"identity-go/internal/domain/entity"
	"identity-go/internal/domain/repository"
)

// Errors
var (
	ErrInvalidCredentials = errors.New("credenciais inválidas")
	ErrUserInactive       = errors.New("usuário inativo")
)

// LoginRequest representa os dados de entrada para login.
type LoginRequest struct {
	Username string
	Password string
}

// LoginResponse representa os dados de saída após login bem-sucedido.
type LoginResponse struct {
	User         *entity.User
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// AuthService defines the interface for authentication operations required by LoginUseCase.
type AuthService interface {
	VerifyPassword(ctx context.Context, hashedPassword, providedPassword string) (bool, error)
	GenerateToken(ctx context.Context, user *entity.User, expiry time.Duration) (string, error)
}

// LoginUseCase implementa o caso de uso de login de usuário.
type LoginUseCase struct {
	userRepo    repository.UserRepository
	authService AuthService // Use the local interface definition
}

// NewLoginUseCase cria uma nova instância do caso de uso de login.
func NewLoginUseCase(userRepo repository.UserRepository, authService AuthService) *LoginUseCase { // Use the local interface definition
	return &LoginUseCase{
		userRepo:    userRepo,
		authService: authService,
	}
}

// Execute realiza o processo de login e retorna tokens de acesso em caso de sucesso.
func (u *LoginUseCase) Execute(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	// Buscar usuário pelo username
	user, err := u.userRepo.FindByUsername(ctx, req.Username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Verificar se o usuário está ativo
	if !user.IsActive() {
		return nil, ErrUserInactive
	}

	// Verificar senha
	valid, err := u.authService.VerifyPassword(ctx, user.HashedPassword, req.Password)
	if err != nil || !valid {
		return nil, ErrInvalidCredentials
	}

	// Atualizar último login
	now := time.Now()
	user.SetLastLogin(now)
	if err := u.userRepo.Update(ctx, user); err != nil {
		// Não crítico, apenas logar erro
		// log.Printf("Erro ao atualizar data de último login: %v", err)
	}

	// Gerar tokens
	accessTokenExpiry := 30 * time.Minute
	accessToken, err := u.authService.GenerateToken(ctx, user, accessTokenExpiry)
	if err != nil {
		return nil, err
	}

	refreshTokenExpiry := 7 * 24 * time.Hour // 1 semana
	refreshToken, err := u.authService.GenerateToken(ctx, user, refreshTokenExpiry)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    now.Add(accessTokenExpiry),
	}, nil
}
