// Package repository contém interfaces para os repositórios de dados.
package repository

import (
	"context"

	"identity-go/internal/domain/entity"
)

// UserRepository define as operações disponíveis para persistência de usuários.
type UserRepository interface {
	// Save persiste um usuário no repositório.
	Save(ctx context.Context, user *entity.User) error

	// FindByID busca um usuário pelo seu ID.
	FindByID(ctx context.Context, id string) (*entity.User, error)

	// FindByUsername busca um usuário pelo seu nome de usuário.
	FindByUsername(ctx context.Context, username string) (*entity.User, error)

	// FindByEmail busca um usuário pelo seu email.
	FindByEmail(ctx context.Context, email string) (*entity.User, error)

	// Delete remove um usuário do repositório.
	Delete(ctx context.Context, id string) error

	// Update atualiza os dados de um usuário existente.
	Update(ctx context.Context, user *entity.User) error
}
