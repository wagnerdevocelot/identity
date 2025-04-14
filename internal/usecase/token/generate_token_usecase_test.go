package token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock do TokenRepository
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) StoreAccessToken(ctx context.Context, token string, clientID string, userID string, expiry time.Time, scope string) error {
	args := m.Called(ctx, token, clientID, userID, expiry, scope)
	return args.Error(0)
}

func (m *MockTokenRepository) StoreRefreshToken(ctx context.Context, token string, clientID string, userID string, expiry time.Time, scope string) error {
	args := m.Called(ctx, token, clientID, userID, expiry, scope)
	return args.Error(0)
}

func (m *MockTokenRepository) RevokeToken(ctx context.Context, token string, tokenType string) error {
	args := m.Called(ctx, token, tokenType)
	return args.Error(0)
}

// Mock do ClientRepository
type MockClientRepository struct {
	mock.Mock
}

func (m *MockClientRepository) ValidateClient(ctx context.Context, clientID string, clientSecret string) (bool, error) {
	args := m.Called(ctx, clientID, clientSecret)
	return args.Bool(0), args.Error(1)
}

func (m *MockClientRepository) IsGrantSupported(ctx context.Context, clientID string, grant GrantType) (bool, error) {
	args := m.Called(ctx, clientID, grant)
	return args.Bool(0), args.Error(1)
}

func (m *MockClientRepository) ValidateScope(ctx context.Context, clientID string, scope string) (string, error) {
	args := m.Called(ctx, clientID, scope)
	return args.String(0), args.Error(1)
}

func TestGenerateTokenUseCase_Execute_ClientCredentials_Success(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypeClientCredentials).Return(true, nil)
	mockClientRepo.On("ValidateScope", ctx, "client123", "api:read").Return("api:read", nil)

	// Expectativa para armazenamento do token - não nos importamos com a hora exata, mas precisamos capturá-la
	mockTokenRepo.On("StoreAccessToken",
		ctx,
		"mock_access_token_client123",
		"client123",
		"",
		mock.AnythingOfType("time.Time"),
		"api:read").Return(nil)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act
	req := GenerateTokenRequest{
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "client123",
		ClientSecret: "secret456",
		Scope:        "api:read",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "mock_access_token_client123", response.AccessToken)
	assert.Equal(t, "bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.Equal(t, "api:read", response.Scope)

	// Verificar se o token expira aproximadamente em 1 hora (3600 segundos)
	assert.WithinDuration(t, time.Now().Add(time.Hour), response.ExpiresAt, time.Second)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}

func TestGenerateTokenUseCase_Execute_InvalidClient(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks - cliente inválido
	mockClientRepo.On("ValidateClient", ctx, "invalid_client", "wrong_secret").Return(false, nil)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act
	req := GenerateTokenRequest{
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "invalid_client",
		ClientSecret: "wrong_secret",
		Scope:        "api:read",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidClient, err)
	assert.Nil(t, response)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
	mockTokenRepo.AssertNotCalled(t, "StoreAccessToken")
}

func TestGenerateTokenUseCase_Execute_UnsupportedGrant(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	// Cliente não suporta grant_type password
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypePassword).Return(false, nil)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act
	req := GenerateTokenRequest{
		GrantType:    GrantTypePassword,
		ClientID:     "client123",
		ClientSecret: "secret456",
		Username:     "user",
		Password:     "pass",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidGrantType, err)
	assert.Nil(t, response)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
}

func TestGenerateTokenUseCase_Execute_InvalidScope(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypeClientCredentials).Return(true, nil)
	// Escopo inválido
	mockClientRepo.On("ValidateScope", ctx, "client123", "invalid:scope").Return("", ErrInvalidScope)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act
	req := GenerateTokenRequest{
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "client123",
		ClientSecret: "secret456",
		Scope:        "invalid:scope",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidScope, err)
	assert.Nil(t, response)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
}

func TestGenerateTokenUseCase_Execute_RefreshToken_Success(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypeRefreshToken).Return(true, nil)
	mockClientRepo.On("ValidateScope", ctx, "client123", "api:read").Return("api:read", nil)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act
	req := GenerateTokenRequest{
		GrantType:    GrantTypeRefreshToken,
		ClientID:     "client123",
		ClientSecret: "secret456",
		RefreshToken: "old_refresh_token",
		Scope:        "api:read",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "new_access_token_client123", response.AccessToken)
	assert.Equal(t, "new_refresh_token_client123", response.RefreshToken)
	assert.Equal(t, "bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.Equal(t, "api:read", response.Scope)

	// Verificar se o token expira aproximadamente em 1 hora (3600 segundos)
	assert.WithinDuration(t, time.Now().Add(time.Hour), response.ExpiresAt, time.Second)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
}

func TestGenerateTokenUseCase_Execute_AuthorizationCode_Success(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypeAuthorizationCode).Return(true, nil)
	mockClientRepo.On("ValidateScope", ctx, "client123", "openid profile").Return("openid profile", nil)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act
	req := GenerateTokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     "client123",
		ClientSecret: "secret456",
		Code:         "auth_code_123",
		RedirectURI:  "https://client.example.com/callback",
		Scope:        "openid profile",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "auth_code_access_token_client123", response.AccessToken)
	assert.Equal(t, "auth_code_refresh_token_client123", response.RefreshToken)
	assert.Equal(t, "bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.Equal(t, "openid profile", response.Scope)

	// Verificar se o token expira aproximadamente em 1 hora (3600 segundos)
	assert.WithinDuration(t, time.Now().Add(time.Hour), response.ExpiresAt, time.Second)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
}

func TestGenerateTokenUseCase_Execute_AuthorizationCode_MissingParams(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypeAuthorizationCode).Return(true, nil)
	mockClientRepo.On("ValidateScope", ctx, "client123", "openid profile").Return("openid profile", nil)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act - código de autorização ausente
	req := GenerateTokenRequest{
		GrantType:    GrantTypeAuthorizationCode,
		ClientID:     "client123",
		ClientSecret: "secret456",
		RedirectURI:  "https://client.example.com/callback",
		Scope:        "openid profile",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "código ou redirect_uri inválidos")

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
}

func TestGenerateTokenUseCase_Execute_Password_Success(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypePassword).Return(true, nil)
	mockClientRepo.On("ValidateScope", ctx, "client123", "api:read api:write").Return("api:read api:write", nil)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act
	req := GenerateTokenRequest{
		GrantType:    GrantTypePassword,
		ClientID:     "client123",
		ClientSecret: "secret456",
		Username:     "testuser",
		Password:     "testpass",
		Scope:        "api:read api:write",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, "password_access_token_testuser", response.AccessToken)
	assert.Equal(t, "password_refresh_token_testuser", response.RefreshToken)
	assert.Equal(t, "bearer", response.TokenType)
	assert.Equal(t, 3600, response.ExpiresIn)
	assert.Equal(t, "api:read api:write", response.Scope)

	// Verificar se o token expira aproximadamente em 1 hora (3600 segundos)
	assert.WithinDuration(t, time.Now().Add(time.Hour), response.ExpiresAt, time.Second)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
}

func TestGenerateTokenUseCase_Execute_Password_MissingCredentials(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypePassword).Return(true, nil)
	mockClientRepo.On("ValidateScope", ctx, "client123", "api:read").Return("api:read", nil)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act - username ausente
	req := GenerateTokenRequest{
		GrantType:    GrantTypePassword,
		ClientID:     "client123",
		ClientSecret: "secret456",
		Password:     "testpass", // sem username
		Scope:        "api:read",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "credenciais de usuário inválidas")

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
}

func TestGenerateTokenUseCase_Execute_TokenStorageError(t *testing.T) {
	// Arrange
	mockTokenRepo := new(MockTokenRepository)
	mockClientRepo := new(MockClientRepository)

	ctx := context.Background()
	storageError := errors.New("erro ao armazenar token")

	// Setup expectativas dos mocks
	mockClientRepo.On("ValidateClient", ctx, "client123", "secret456").Return(true, nil)
	mockClientRepo.On("IsGrantSupported", ctx, "client123", GrantTypeClientCredentials).Return(true, nil)
	mockClientRepo.On("ValidateScope", ctx, "client123", "api:read").Return("api:read", nil)

	// Simular erro ao armazenar o token
	mockTokenRepo.On("StoreAccessToken",
		ctx,
		"mock_access_token_client123",
		"client123",
		"",
		mock.AnythingOfType("time.Time"),
		"api:read").Return(storageError)

	// Criar o caso de uso
	tokenUseCase := NewGenerateTokenUseCase(mockTokenRepo, mockClientRepo)

	// Act
	req := GenerateTokenRequest{
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "client123",
		ClientSecret: "secret456",
		Scope:        "api:read",
	}

	response, err := tokenUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, storageError, err)
	assert.Nil(t, response)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockClientRepo.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}
