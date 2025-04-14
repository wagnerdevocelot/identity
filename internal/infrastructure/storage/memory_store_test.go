package storage

import (
	"context"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
)

// TestNewInMemoryStore testa a criação do armazenamento em memória
func TestNewInMemoryStore(t *testing.T) {
	store := NewInMemoryStore()

	// Verificar se o armazenamento está inicializado corretamente
	assert.NotNil(t, store.Clients)
	assert.NotNil(t, store.AuthorizeCodes)
	assert.NotNil(t, store.AccessTokens)
	assert.NotNil(t, store.RefreshTokens)
	assert.NotNil(t, store.OIDCSessions)
	assert.NotNil(t, store.PKCESessions)

	// Verificar se o cliente de teste foi criado corretamente
	client, err := store.GetClient(context.Background(), "my-test-client")
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "my-test-client", client.GetID())
}

// Cria um cliente OAuth2 para os testes
func createTestClient() fosite.Client {
	return &fosite.DefaultClient{
		ID:            "test-client",
		Secret:        []byte("test-secret"),
		RedirectURIs:  []string{"https://test-client.example.com/callback"},
		ResponseTypes: []string{"code", "token"},
		GrantTypes:    []string{"authorization_code", "refresh_token", "client_credentials"},
		Scopes:        []string{"openid", "profile", "email"},
	}
}

// Cria uma requisição para os testes
func createTestRequester(client fosite.Client, session fosite.Session) fosite.Requester {
	return &fosite.Request{
		Client:  client,
		Session: session,
	}
}

// TestClientCRUD testa as operações CRUD para clientes OAuth2
func TestClientCRUD(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	client := createTestClient()

	// Teste de CreateClient
	err := store.CreateClient(ctx, client)
	assert.NoError(t, err)

	// Teste de GetClient
	retrievedClient, err := store.GetClient(ctx, "test-client")
	assert.NoError(t, err)
	assert.Equal(t, client.GetID(), retrievedClient.GetID())

	// Teste de UpdateClient
	updatedClient := &fosite.DefaultClient{
		ID:            "test-client",
		Secret:        []byte("updated-secret"),
		RedirectURIs:  []string{"https://updated-client.example.com/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"openid", "profile"},
	}

	err = store.UpdateClient(ctx, updatedClient)
	assert.NoError(t, err)

	retrievedUpdatedClient, err := store.GetClient(ctx, "test-client")
	assert.NoError(t, err)
	assert.Equal(t, "test-client", retrievedUpdatedClient.GetID())
	assert.Equal(t, []string{"https://updated-client.example.com/callback"}, retrievedUpdatedClient.GetRedirectURIs())

	// Teste de DeleteClient
	err = store.DeleteClient(ctx, "test-client")
	assert.NoError(t, err)

	// Verificar que o cliente foi excluído
	_, err = store.GetClient(ctx, "test-client")
	assert.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrNotFound)

	// Teste de tentar atualizar um cliente inexistente
	err = store.UpdateClient(ctx, updatedClient)
	assert.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrNotFound)

	// Teste de tentar excluir um cliente inexistente
	err = store.DeleteClient(ctx, "nonexistent-client")
	assert.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}

// TestTokenOperations testa as operações de tokens
func TestTokenOperations(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	client := createTestClient()
	session := &openid.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().Add(time.Hour),
			fosite.RefreshToken:  time.Now().Add(time.Hour * 24 * 7),
			fosite.AuthorizeCode: time.Now().Add(time.Minute * 10),
		},
	}
	requester := createTestRequester(client, session)

	// Registrar o cliente primeiro
	err := store.CreateClient(ctx, client)
	assert.NoError(t, err)

	// Teste do token de acesso
	err = store.CreateAccessTokenSession(ctx, "access-token-signature", requester)
	assert.NoError(t, err)

	retrievedRequester, err := store.GetAccessTokenSession(ctx, "access-token-signature", session)
	assert.NoError(t, err)
	assert.Equal(t, client.GetID(), retrievedRequester.GetClient().GetID())

	// Teste do código de autorização
	err = store.CreateAuthorizeCodeSession(ctx, "auth-code-signature", requester)
	assert.NoError(t, err)

	retrievedAuthCodeRequester, err := store.GetAuthorizeCodeSession(ctx, "auth-code-signature", session)
	assert.NoError(t, err)
	assert.Equal(t, client.GetID(), retrievedAuthCodeRequester.GetClient().GetID())

	// Teste do token de atualização
	err = store.CreateRefreshTokenSession(ctx, "refresh-token-signature", client.GetID(), requester)
	assert.NoError(t, err)

	retrievedRefreshTokenRequester, err := store.GetRefreshTokenSession(ctx, "refresh-token-signature", session)
	assert.NoError(t, err)
	assert.Equal(t, client.GetID(), retrievedRefreshTokenRequester.GetClient().GetID())

	// Teste de revogação de token de acesso
	err = store.RevokeAccessToken(ctx, "access-token-signature")
	assert.NoError(t, err)

	_, err = store.GetAccessTokenSession(ctx, "access-token-signature", session)
	assert.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrNotFound)

	// Teste de revogação de token de atualização
	err = store.RevokeRefreshToken(ctx, "refresh-token-signature")
	assert.NoError(t, err)

	_, err = store.GetRefreshTokenSession(ctx, "refresh-token-signature", session)
	assert.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrNotFound)

	// Teste de invalidação de código de autorização
	err = store.InvalidateAuthorizeCodeSession(ctx, "auth-code-signature")
	assert.NoError(t, err)

	_, err = store.GetAuthorizeCodeSession(ctx, "auth-code-signature", session)
	assert.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}

// TestOIDCOperations testa as operações OpenID Connect
func TestOIDCOperations(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	client := createTestClient()
	session := &openid.DefaultSession{
		Subject: "user123",
		Claims: &jwt.IDTokenClaims{
			Subject:  "user123",
			Issuer:   "https://auth.example.com",
			Audience: []string{"https://api.example.com"},
			Extra: map[string]interface{}{
				"name":           "Test User",
				"email":          "test@example.com",
				"email_verified": true,
			},
		},
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().Add(time.Hour),
			fosite.RefreshToken:  time.Now().Add(time.Hour * 24 * 7),
			fosite.AuthorizeCode: time.Now().Add(time.Minute * 10),
		},
	}
	requester := createTestRequester(client, session)

	// Registrar o cliente primeiro
	err := store.CreateClient(ctx, client)
	assert.NoError(t, err)

	// Criar uma sessão OpenID Connect
	err = store.CreateOpenIDConnectSession(ctx, "oidc-code", requester)
	assert.NoError(t, err)

	// Recuperar a sessão
	retrievedSession, err := store.GetOpenIDConnectSession(ctx, "oidc-code", requester)
	assert.NoError(t, err)
	assert.Equal(t, client.GetID(), retrievedSession.GetClient().GetID())

	// Excluir a sessão
	err = store.DeleteOpenIDConnectSession(ctx, "oidc-code")
	assert.NoError(t, err)

	// Verificar que a sessão foi excluída
	_, err = store.GetOpenIDConnectSession(ctx, "oidc-code", requester)
	assert.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}

// TestPKCEOperations testa as operações PKCE
func TestPKCEOperations(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	client := createTestClient()
	session := &openid.DefaultSession{}
	requester := createTestRequester(client, session)

	// Criar uma sessão PKCE
	err := store.CreatePKCERequestSession(ctx, "pkce-challenge", requester)
	assert.NoError(t, err)

	// Recuperar a sessão
	retrievedSession, err := store.GetPKCERequestSession(ctx, "pkce-challenge", session)
	assert.NoError(t, err)
	assert.Equal(t, client.GetID(), retrievedSession.GetClient().GetID())

	// Excluir a sessão
	err = store.DeletePKCERequestSession(ctx, "pkce-challenge")
	assert.NoError(t, err)

	// Verificar que a sessão foi excluída
	_, err = store.GetPKCERequestSession(ctx, "pkce-challenge", session)
	assert.Error(t, err)
	assert.ErrorIs(t, err, fosite.ErrNotFound)
}

// TestJWTOperations testa as operações relacionadas a JWT
func TestJWTOperations(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()

	// Teste de validação de JWT não utilizado
	err := store.ClientAssertionJWTValid(ctx, "new-jwt-id")
	assert.NoError(t, err)

	// Teste de marcação de JWT como usado
	expiry := time.Now().Add(time.Hour)
	err = store.SetClientAssertionJWT(ctx, "new-jwt-id", expiry)
	assert.NoError(t, err)

	// Teste de validação de JWT já utilizado
	err = store.ClientAssertionJWTValid(ctx, "new-jwt-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "já foi utilizado")

	// Teste de marcação de JWT já utilizado
	err = store.SetClientAssertionJWT(ctx, "new-jwt-id", expiry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "já usado")

	// Teste JWT com data de expiração no passado
	expiredJWTID := "expired-jwt"
	expiredTime := time.Now().Add(-time.Hour) // Uma hora atrás
	_ = store.SetClientAssertionJWT(ctx, expiredJWTID, expiredTime)

	// JWT expirado deve ser tratado como desconhecido/novo
	err = store.ClientAssertionJWTValid(ctx, expiredJWTID)
	assert.NoError(t, err)
}

// TestGenericTokenInterface testa a interface genérica de token
func TestGenericTokenInterface(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	client := createTestClient()
	session := &openid.DefaultSession{}
	requester := createTestRequester(client, session)

	err := store.CreateClient(ctx, client)
	assert.NoError(t, err)

	// Teste de criação de token via interface genérica
	err = store.CreateToken(ctx, "access_token", "generic-access-token", client.GetID(), requester)
	assert.NoError(t, err)

	err = store.CreateToken(ctx, "refresh_token", "generic-refresh-token", client.GetID(), requester)
	assert.NoError(t, err)

	err = store.CreateToken(ctx, "authorize_code", "generic-auth-code", client.GetID(), requester)
	assert.NoError(t, err)

	// Teste de tipo de token inválido
	err = store.CreateToken(ctx, "invalid_token_type", "invalid-token", client.GetID(), requester)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tipo de token não suportado")

	// Teste de recuperação de token via interface genérica
	retrievedToken, err := store.GetToken(ctx, "access_token", "generic-access-token")
	assert.NoError(t, err)
	retrievedRequester, ok := retrievedToken.(fosite.Requester)
	assert.True(t, ok)
	assert.Equal(t, client.GetID(), retrievedRequester.GetClient().GetID())

	// Teste de exclusão de token via interface genérica
	err = store.DeleteToken(ctx, "access_token", "generic-access-token")
	assert.NoError(t, err)

	// Verificar se o token foi excluído
	_, err = store.GetToken(ctx, "access_token", "generic-access-token")
	assert.Error(t, err)

	// Teste de revogação de token via interface genérica
	err = store.RevokeToken(ctx, "refresh_token", "generic-refresh-token")
	assert.NoError(t, err)

	// Verificar se o token foi revogado
	_, err = store.GetToken(ctx, "refresh_token", "generic-refresh-token")
	assert.Error(t, err)
}

// TestGenericSessionInterface testa a interface genérica de sessão
func TestGenericSessionInterface(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	client := createTestClient()
	session := &openid.DefaultSession{}
	requester := createTestRequester(client, session)

	// Teste de criação de sessão via interface genérica
	err := store.CreateSession(ctx, "openid", "generic-openid-session", requester)
	assert.NoError(t, err)

	err = store.CreateSession(ctx, "pkce", "generic-pkce-session", requester)
	assert.NoError(t, err)

	// Teste de tipo de sessão inválida
	err = store.CreateSession(ctx, "invalid_session_type", "invalid-session", requester)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tipo de sessão não suportado")

	// Teste de recuperação de sessão via interface genérica
	retrievedSession, err := store.GetSession(ctx, "pkce", "generic-pkce-session")
	assert.NoError(t, err)
	retrievedRequester, ok := retrievedSession.(fosite.Requester)
	assert.True(t, ok)
	assert.Equal(t, client.GetID(), retrievedRequester.GetClient().GetID())

	// Teste de exclusão de sessão via interface genérica
	err = store.DeleteSession(ctx, "pkce", "generic-pkce-session")
	assert.NoError(t, err)

	// Verificar se a sessão foi excluída
	_, err = store.GetSession(ctx, "pkce", "generic-pkce-session")
	assert.Error(t, err)
}
