// Package auth contém implementações relacionadas à autenticação e autorização.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"time"

	"identity-go/internal/infrastructure/storage"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

// SetupOAuth2Provider configura e retorna um provedor OAuth2 com todas as suas dependências
// jwtSecret é a chave secreta usada para assinar tokens JWT. Deve ter 32 bytes.
func SetupOAuth2Provider(jwtSecret []byte) (fosite.OAuth2Provider, *storage.InMemoryStore) {
	// Inicializar o armazenamento
	store := storage.NewInMemoryStore()

	// Configuração do Fosite usando fosite.Config (v0.49.0+)
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:            time.Minute * 30,
		AuthorizeCodeLifespan:          time.Minute * 10,
		RefreshTokenLifespan:           time.Hour * 24 * 7,
		SendDebugMessagesToClients:     true,
		ScopeStrategy:                  fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
		RedirectSecureChecker:          fosite.IsRedirectURISecureStrict,
		MinParameterEntropy:            fosite.MinParameterEntropy,
		EnforcePKCE:                    false,
		EnablePKCEPlainChallengeMethod: false,
		TokenURL:                       "http://localhost:8080/oauth2/token",
		GlobalSecret:                   jwtSecret,
	}

	// Gerar chave RSA para assinatura de JWTs (Tokens de ID)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Falha ao gerar chave RSA: %v", err)
	}

	// Inicializar o provedor usando compose.Compose
	provider := compose.Compose(
		fositeConfig,
		store,
		// Configurar estratégias usando CommonStrategy
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(fositeConfig),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(func(ctx context.Context) (interface{}, error) { return privateKey, nil }, fositeConfig),
		},

		// Lista de Handler Factories habilitados:
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,

		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectRefreshFactory,

		compose.OAuth2PKCEFactory,
	)

	return provider, store
}
