// Package entity contém as entidades do domínio.
package entity

import (
	"errors"
	"time"
)

// User representa um usuário do sistema.
type User struct {
	ID             string
	Username       string
	Email          string
	HashedPassword string
	FirstName      string
	LastName       string
	Active         bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastLoginAt    *time.Time
}

// Errors
var (
	ErrInvalidUsername = errors.New("nome de usuário inválido")
	ErrInvalidEmail    = errors.New("email inválido")
	ErrInvalidPassword = errors.New("senha inválida")
)

// NewUser cria uma nova instância de User.
func NewUser(id, username, email, hashedPassword string) (*User, error) {
	// Validação básica
	if username == "" {
		return nil, ErrInvalidUsername
	}

	if email == "" {
		return nil, ErrInvalidEmail
	}

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
	if email == "" {
		return ErrInvalidEmail
	}

	u.FirstName = firstName
	u.LastName = lastName
	u.Email = email
	u.UpdatedAt = time.Now()

	return nil
}
