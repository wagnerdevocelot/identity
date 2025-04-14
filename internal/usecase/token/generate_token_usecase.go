// Package token contém os casos de uso relacionados ao gerenciamento de tokens.
package token

import (
	"context"
	"errors"
	"time"
)

// Errors
var (
	ErrInvalidGrantType = errors.New("tipo de concessão inválido")
	ErrInvalidScope     = errors.New("escopo inválido")
	ErrInvalidClient    = errors.New("cliente inválido")
)

// GrantType representa os tipos de concessão OAuth2
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypePassword          GrantType = "password"
)

// GenerateTokenRequest representa os dados de entrada para geração de token.
type GenerateTokenRequest struct {
	GrantType    GrantType
	ClientID     string
	ClientSecret string
	Code         string // Para authorization_code
	RedirectURI  string // Para authorization_code
	RefreshToken string // Para refresh_token
	Username     string // Para password
	Password     string // Para password
	Scope        string // Opcional
}

// TokenResponse representa os dados de saída após geração de token.
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	Scope        string
	IDToken      string // Para OpenID Connect
	ExpiresAt    time.Time
}

// GenerateTokenUseCase implementa o caso de uso de geração de token OAuth2.
type GenerateTokenUseCase struct {
	tokenRepository  TokenRepository
	clientRepository ClientRepository
}

// TokenRepository define o contrato para operações de persistência de tokens.
type TokenRepository interface {
	StoreAccessToken(ctx context.Context, token string, clientID string, userID string, expiry time.Time, scope string) error
	StoreRefreshToken(ctx context.Context, token string, clientID string, userID string, expiry time.Time, scope string) error
	RevokeToken(ctx context.Context, token string, tokenType string) error
}

// ClientRepository define o contrato para operações com clientes OAuth2.
type ClientRepository interface {
	ValidateClient(ctx context.Context, clientID string, clientSecret string) (bool, error)
	IsGrantSupported(ctx context.Context, clientID string, grant GrantType) (bool, error)
	ValidateScope(ctx context.Context, clientID string, scope string) (string, error)
}

// NewGenerateTokenUseCase cria uma nova instância do caso de uso de geração de token.
func NewGenerateTokenUseCase(tokenRepo TokenRepository, clientRepo ClientRepository) *GenerateTokenUseCase {
	return &GenerateTokenUseCase{
		tokenRepository:  tokenRepo,
		clientRepository: clientRepo,
	}
}

// Execute realiza o processo de geração de token conforme o tipo de concessão.
func (u *GenerateTokenUseCase) Execute(ctx context.Context, req GenerateTokenRequest) (*TokenResponse, error) {
	// Validar cliente
	valid, err := u.clientRepository.ValidateClient(ctx, req.ClientID, req.ClientSecret)
	if err != nil || !valid {
		return nil, ErrInvalidClient
	}

	// Validar se o tipo de concessão é suportado pelo cliente
	supported, err := u.clientRepository.IsGrantSupported(ctx, req.ClientID, req.GrantType)
	if err != nil || !supported {
		return nil, ErrInvalidGrantType
	}

	// Validar escopo
	finalScope, err := u.clientRepository.ValidateScope(ctx, req.ClientID, req.Scope)
	if err != nil {
		return nil, ErrInvalidScope
	}

	// Tratamento específico para cada tipo de concessão
	switch req.GrantType {
	case GrantTypeClientCredentials:
		return u.handleClientCredentials(ctx, req, finalScope)
	case GrantTypeRefreshToken:
		return u.handleRefreshToken(ctx, req, finalScope)
	case GrantTypeAuthorizationCode:
		return u.handleAuthorizationCode(ctx, req, finalScope)
	case GrantTypePassword:
		return u.handlePassword(ctx, req, finalScope)
	default:
		return nil, ErrInvalidGrantType
	}
}

// handleClientCredentials implementa a geração de token para o fluxo client_credentials
// utilizando os parâmetros recebidos
func (u *GenerateTokenUseCase) handleClientCredentials(ctx context.Context, req GenerateTokenRequest, scope string) (*TokenResponse, error) {
	// Em uma implementação real, geraria tokens reais e os armazenaria
	// Por enquanto, retornamos um mock simples
	now := time.Now()
	expiresIn := 3600 // 1 hora

	// Usar os parâmetros recebidos para gerar um token real
	accessToken := "mock_access_token_" + req.ClientID

	// Em uma implementação real, armazenar o token no repositório
	err := u.tokenRepository.StoreAccessToken(
		ctx,
		accessToken,
		req.ClientID,
		"", // Não há userID no fluxo client_credentials
		now.Add(time.Duration(expiresIn)*time.Second),
		scope,
	)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "bearer",
		ExpiresIn:   expiresIn,
		Scope:       scope,
		ExpiresAt:   now.Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

// handleRefreshToken implementa a geração de novo access_token a partir de um refresh_token
func (u *GenerateTokenUseCase) handleRefreshToken(ctx context.Context, req GenerateTokenRequest, scope string) (*TokenResponse, error) {
	// Em uma implementação real:
	// 1. Validar o refresh_token
	// 2. Revogar o token antigo
	// 3. Gerar novos tokens
	// 4. Armazenar os novos tokens

	// Usar o contexto para cancelamento e timeout
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continuar processamento
	}

	// Exemplo simplificado usando os parâmetros
	now := time.Now()
	expiresIn := 3600

	return &TokenResponse{
		AccessToken:  "new_access_token_" + req.ClientID,
		RefreshToken: "new_refresh_token_" + req.ClientID,
		TokenType:    "bearer",
		ExpiresIn:    expiresIn,
		Scope:        scope,
		ExpiresAt:    now.Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

// handleAuthorizationCode implementa a troca do código de autorização por tokens
func (u *GenerateTokenUseCase) handleAuthorizationCode(_ context.Context, req GenerateTokenRequest, scope string) (*TokenResponse, error) {
	// Em uma implementação real:
	// 1. Validar o código de autorização
	// 2. Verificar se o redirect_uri corresponde ao original
	// 3. Gerar tokens
	// 4. Armazenar tokens

	// Validar o code e redirect_uri da requisição
	if req.Code == "" || req.RedirectURI == "" {
		return nil, errors.New("código ou redirect_uri inválidos")
	}

	// Usar o contexto para logging estruturado ou tracing
	// logger := ctx.Value("logger").(Logger)
	// logger.Info("Processando código de autorização", "client_id", req.ClientID, "scope", scope)

	now := time.Now()
	expiresIn := 3600

	return &TokenResponse{
		AccessToken:  "auth_code_access_token_" + req.ClientID,
		RefreshToken: "auth_code_refresh_token_" + req.ClientID,
		TokenType:    "bearer",
		ExpiresIn:    expiresIn,
		Scope:        scope,
		ExpiresAt:    now.Add(time.Duration(expiresIn) * time.Second),
		// IDToken seria gerado aqui se o escopo incluir 'openid'
	}, nil
}

// handlePassword implementa o fluxo de autenticação com usuário e senha
func (u *GenerateTokenUseCase) handlePassword(_ context.Context, req GenerateTokenRequest, scope string) (*TokenResponse, error) {
	// Em uma implementação real:
	// 1. Autenticar o usuário
	// 2. Validar permissões
	// 3. Gerar tokens
	// 4. Armazenar tokens

	// Validar credenciais do usuário na requisição
	if req.Username == "" || req.Password == "" {
		return nil, errors.New("credenciais de usuário inválidas")
	}

	// Verificar se o escopo solicitado é permitido para este usuário
	if !validateUserScope(req.Username, scope) {
		return nil, ErrInvalidScope
	}

	now := time.Now()
	expiresIn := 3600

	return &TokenResponse{
		AccessToken:  "password_access_token_" + req.Username,
		RefreshToken: "password_refresh_token_" + req.Username,
		TokenType:    "bearer",
		ExpiresIn:    expiresIn,
		Scope:        scope,
		ExpiresAt:    now.Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

// Função auxiliar para validar escopos do usuário
func validateUserScope(_ string, _ string) bool {
	// Implementação fictícia - em um sistema real, verificaria permissões do usuário
	return true
}
