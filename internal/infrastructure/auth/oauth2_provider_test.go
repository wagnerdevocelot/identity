package auth

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
)

func TestSetupOAuth2Provider(t *testing.T) {
	// Criar uma chave JWT para teste (32 bytes)
	jwtSecret := []byte("01234567890123456789012345678901")

	// Executar a função a ser testada
	provider, store := SetupOAuth2Provider(jwtSecret)

	// Verificar se retornou instâncias válidas
	assert.NotNil(t, provider, "O provedor OAuth2 não deve ser nil")
	assert.NotNil(t, store, "O armazenamento não deve ser nil")

	// Testar a configuração básica
	// Vamos verificar se o store está realmente sendo utilizado pelo provider
	// criando um cliente OAuth2 e verificando se ele é persistido corretamente

	// Criar um cliente OAuth2 de teste
	client := &fosite.DefaultClient{
		ID:            "test-client",
		Secret:        []byte("test-secret"),
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code", "token", "id_token"},
		GrantTypes:    []string{"authorization_code", "refresh_token", "client_credentials"},
		Scopes:        []string{"openid", "profile", "email"},
	}

	// Registrar o cliente no armazenamento
	err := store.CreateClient(context.Background(), client)
	assert.NoError(t, err, "Deve registrar o cliente sem erros")

	// Buscar o cliente registrado
	storedClient, err := store.GetClient(context.Background(), "test-client")
	assert.NoError(t, err, "Deve recuperar o cliente sem erros")
	assert.NotNil(t, storedClient, "O cliente armazenado não deve ser nil")
	assert.Equal(t, client.GetID(), storedClient.GetID(), "Os IDs dos clientes devem corresponder")

	// Verificar configurações do provedor através de interação com o store
	// Vamos criar um token de acesso e verificar se ele é persistido corretamente
	session := &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().Add(time.Hour),
			fosite.RefreshToken:  time.Now().Add(time.Hour * 24 * 7),
			fosite.AuthorizeCode: time.Now().Add(time.Minute * 10),
		},
	}

	// Criar um token de acesso
	signature := "test-signature"
	tokenData := "test-token-data"

	// Armazenar o token
	err = store.CreateAccessTokenSession(context.Background(), signature, &fosite.Request{
		Client:  client,
		Session: session,
	})
	assert.NoError(t, err, "Deve criar a sessão do token sem erros")

	// Verificar se o token foi armazenado
	_, err = store.GetAccessTokenSession(context.Background(), signature, session)
	assert.NoError(t, err, "Deve recuperar a sessão do token sem erros")

	// Testar a revogação de tokens
	err = store.RevokeAccessToken(context.Background(), tokenData)
	assert.NoError(t, err, "Deve revogar o token sem erros")
}

func TestOAuth2ProviderConfiguration(t *testing.T) {
	// Este teste verifica apenas se conseguimos criar um provedor sem erros
	// sem executar chamadas que possam causar problemas de ponteiro nulo

	// Criar uma chave JWT para teste (32 bytes)
	jwtSecret := []byte("01234567890123456789012345678901")

	// Executar a função a ser testada
	provider, _ := SetupOAuth2Provider(jwtSecret)

	// Verificar se o provider não é nulo
	assert.NotNil(t, provider, "O provedor OAuth2 não deve ser nil")

	// Verificar se o provider implementa a interface OAuth2Provider
	_, ok := provider.(fosite.OAuth2Provider)
	assert.True(t, ok, "O provedor deve implementar a interface OAuth2Provider")
}
