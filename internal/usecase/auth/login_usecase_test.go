package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"identity-go/internal/domain/entity"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock de UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Save(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id string) (*entity.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) FindByUsername(ctx context.Context, username string) (*entity.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) Create(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Update(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// Mock de AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) VerifyPassword(ctx context.Context, hashedPassword, providedPassword string) (bool, error) {
	args := m.Called(ctx, hashedPassword, providedPassword)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthService) GenerateToken(ctx context.Context, user *entity.User, expiry time.Duration) (string, error) {
	args := m.Called(ctx, user, expiry)
	return args.String(0), args.Error(1)
}

func TestLoginUseCase_Execute_Success(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	mockAuthService := new(MockAuthService)

	ctx := context.Background()
	now := time.Now()

	// Criar um usuário de teste
	user := &entity.User{
		ID:             "user123",
		Username:       "testuser",
		HashedPassword: "$2a$10$abcdefghijklmnopqrstuvwxyz123456",
		Email:          "test@example.com",
		Active:         true,
		CreatedAt:      now.Add(-24 * time.Hour),
		UpdatedAt:      now.Add(-24 * time.Hour),
	}

	// Configurar expectativas dos mocks
	mockUserRepo.On("FindByUsername", ctx, "testuser").Return(user, nil)
	mockUserRepo.On("Update", ctx, mock.AnythingOfType("*entity.User")).Return(nil)
	mockAuthService.On("VerifyPassword", ctx, user.HashedPassword, "correctpassword").Return(true, nil)
	mockAuthService.On("GenerateToken", ctx, user, 30*time.Minute).Return("access-token-123", nil)
	mockAuthService.On("GenerateToken", ctx, user, 7*24*time.Hour).Return("refresh-token-456", nil)

	// Criar o caso de uso
	loginUseCase := NewLoginUseCase(mockUserRepo, mockAuthService)

	// Act
	req := LoginRequest{
		Username: "testuser",
		Password: "correctpassword",
	}

	response, err := loginUseCase.Execute(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, user, response.User)
	assert.Equal(t, "access-token-123", response.AccessToken)
	assert.Equal(t, "refresh-token-456", response.RefreshToken)
	assert.WithinDuration(t, now.Add(30*time.Minute), response.ExpiresAt, time.Second)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockUserRepo.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestLoginUseCase_Execute_UserNotFound(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	mockAuthService := new(MockAuthService)

	ctx := context.Background()

	// Configurar expectativa do mock - usuário não encontrado
	mockUserRepo.On("FindByUsername", ctx, "nonexistentuser").Return(nil, errors.New("user not found"))

	// Criar o caso de uso
	loginUseCase := NewLoginUseCase(mockUserRepo, mockAuthService)

	// Act
	req := LoginRequest{
		Username: "nonexistentuser",
		Password: "anypassword",
	}

	response, err := loginUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, ErrInvalidCredentials, err)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockUserRepo.AssertExpectations(t)
	// O authService não deve ser chamado neste caso
}

func TestLoginUseCase_Execute_InactiveUser(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	mockAuthService := new(MockAuthService)

	ctx := context.Background()

	// Criar um usuário inativo para o teste
	user := &entity.User{
		ID:             "user456",
		Username:       "inactiveuser",
		HashedPassword: "$2a$10$abcdefghijklmnopqrstuvwxyz789012",
		Email:          "inactive@example.com",
		Active:         false,
	}

	// Configurar expectativa do mock - usuário inativo
	mockUserRepo.On("FindByUsername", ctx, "inactiveuser").Return(user, nil)

	// Criar o caso de uso
	loginUseCase := NewLoginUseCase(mockUserRepo, mockAuthService)

	// Act
	req := LoginRequest{
		Username: "inactiveuser",
		Password: "anypassword",
	}

	response, err := loginUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, ErrUserInactive, err)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockUserRepo.AssertExpectations(t)
	// O authService não deve ser chamado para verificar a senha neste caso
}

func TestLoginUseCase_Execute_InvalidPassword(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	mockAuthService := new(MockAuthService)

	ctx := context.Background()

	// Criar um usuário de teste
	user := &entity.User{
		ID:             "user789",
		Username:       "activeuser",
		HashedPassword: "$2a$10$abcdefghijklmnopqrstuvwxyz345678",
		Email:          "active@example.com",
		Active:         true,
	}

	// Configurar expectativas dos mocks
	mockUserRepo.On("FindByUsername", ctx, "activeuser").Return(user, nil)
	mockAuthService.On("VerifyPassword", ctx, user.HashedPassword, "wrongpassword").Return(false, nil)

	// Criar o caso de uso
	loginUseCase := NewLoginUseCase(mockUserRepo, mockAuthService)

	// Act
	req := LoginRequest{
		Username: "activeuser",
		Password: "wrongpassword",
	}

	response, err := loginUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, ErrInvalidCredentials, err)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockUserRepo.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}

func TestLoginUseCase_Execute_TokenGenerationFailure(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	mockAuthService := new(MockAuthService)

	ctx := context.Background()

	// Criar um usuário de teste
	user := &entity.User{
		ID:             "user101112",
		Username:       "tokenuser",
		HashedPassword: "$2a$10$abcdefghijklmnopqrstuvwxyz901234",
		Email:          "token@example.com",
		Active:         true,
	}

	tokenError := errors.New("falha na geração do token")

	// Configurar expectativas dos mocks
	mockUserRepo.On("FindByUsername", ctx, "tokenuser").Return(user, nil)
	mockUserRepo.On("Update", ctx, mock.AnythingOfType("*entity.User")).Return(nil)
	mockAuthService.On("VerifyPassword", ctx, user.HashedPassword, "validpassword").Return(true, nil)
	mockAuthService.On("GenerateToken", ctx, user, 30*time.Minute).Return("", tokenError)

	// Criar o caso de uso
	loginUseCase := NewLoginUseCase(mockUserRepo, mockAuthService)

	// Act
	req := LoginRequest{
		Username: "tokenuser",
		Password: "validpassword",
	}

	response, err := loginUseCase.Execute(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, tokenError, err)

	// Verificar se todos os métodos dos mocks foram chamados conforme esperado
	mockUserRepo.AssertExpectations(t)
	mockAuthService.AssertExpectations(t)
}
