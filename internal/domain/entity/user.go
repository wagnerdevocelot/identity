// Package entity contém as entidades do domínio.
package entity

import (
	"errors"
	"regexp"
	"time"
)

// Expressão regular para validação básica de email
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// User representa um usuário do sistema.
type User struct {
	ID             string     // Identificador único do usuário
	Username       string     // Nome de usuário para login
	Email          string     // Email do usuário
	HashedPassword string     // Senha hash do usuário (nunca armazenar em texto plano)
	FirstName      string     // Primeiro nome do usuário
	LastName       string     // Sobrenome do usuário
	Active         bool       // Status de ativação da conta
	CreatedAt      time.Time  // Data e hora de criação da conta
	UpdatedAt      time.Time  // Data e hora da última atualização
	LastLoginAt    *time.Time // Data e hora do último login (ponteiro para indicar valores nulos)
}

// Errors
var (
	ErrInvalidUsername       = errors.New("nome de usuário inválido")
	ErrInvalidEmail          = errors.New("formato de email inválido")
	ErrInvalidPassword       = errors.New("senha inválida")
	ErrPasswordTooShort      = errors.New("senha deve ter pelo menos 8 caracteres")
	ErrUsernameAlreadyExists = errors.New("nome de usuário já está em uso")
	ErrEmailAlreadyExists    = errors.New("email já está em uso")
)

// isValidEmail verifica se um email tem formato válido
func isValidEmail(email string) bool {
	if email == "" {
		return false
	}
	return emailRegex.MatchString(email)
}

// isValidPassword verifica se a senha atende aos requisitos mínimos
// Nota: Este é um exemplo básico. Em produção, você pode querer regras mais rigorosas.
func isValidPassword(password string) bool {
	return len(password) >= 8
}

// NewUser cria uma nova instância de User.
func NewUser(id, username, email, hashedPassword string) (*User, error) {
	// Validação de username
	if username == "" {
		return nil, ErrInvalidUsername
	}

	// Validação de email
	if !isValidEmail(email) {
		return nil, ErrInvalidEmail
	}

	// Validação de senha
	// Nota: Assumimos que a senha já esteja validada antes de ser hasheada
	if hashedPassword == "" {
		return nil, ErrInvalidPassword
	}

	now := time.Now()

	return &User{
		ID:             id,
		Username:       username,
		Email:          email,
		HashedPassword: hashedPassword,
		Active:         true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

// IsActive verifica se o usuário está ativo no sistema.
func (u *User) IsActive() bool {
	return u.Active
}

// SetActive atualiza o status ativo do usuário.
func (u *User) SetActive(active bool) {
	u.Active = active
	u.UpdatedAt = time.Now()
}

// SetLastLogin atualiza o timestamp do último login.
func (u *User) SetLastLogin(t time.Time) {
	u.LastLoginAt = &t
	u.UpdatedAt = time.Now()
}

// FullName retorna o nome completo do usuário.
func (u *User) FullName() string {
	return u.FirstName + " " + u.LastName
}

// UpdateProfile atualiza as informações de perfil do usuário.
func (u *User) UpdateProfile(firstName, lastName, email string) error {
	if !isValidEmail(email) {
		return ErrInvalidEmail
	}

	u.FirstName = firstName
	u.LastName = lastName
	u.Email = email
	u.UpdatedAt = time.Now()

	return nil
}

// ChangePassword atualiza a senha do usuário.
// O parâmetro hashedPassword deve ser o hash da nova senha, não a senha em texto plano.
func (u *User) ChangePassword(hashedPassword string) error {
	if hashedPassword == "" {
		return ErrInvalidPassword
	}

	u.HashedPassword = hashedPassword
	u.UpdatedAt = time.Now()

	return nil
}
