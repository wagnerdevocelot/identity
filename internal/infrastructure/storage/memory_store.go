// Package storage contém as implementações de armazenamento de dados.
package storage

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"golang.org/x/crypto/bcrypt"
)

// InMemoryStore fornece uma implementação simples em memória das interfaces de armazenamento do Fosite.
// AVISO: Isso é apenas para fins de demonstração. Use um armazenamento persistente em produção.
type InMemoryStore struct {
	Clients        map[string]fosite.Client
	AuthorizeCodes map[string]fosite.Requester
	AccessTokens   map[string]fosite.Requester
	RefreshTokens  map[string]map[string]fosite.Requester
	OIDCSessions   map[string]fosite.Requester
	PKCESessions   map[string]fosite.Requester
	Mutex          sync.RWMutex
	UsedJTIs       map[string]time.Time
}

// NewInMemoryStore inicializa um novo armazenamento em memória.
func NewInMemoryStore() *InMemoryStore {
	store := &InMemoryStore{
		Clients:        make(map[string]fosite.Client),
		AuthorizeCodes: make(map[string]fosite.Requester),
		AccessTokens:   make(map[string]fosite.Requester),
		RefreshTokens:  make(map[string]map[string]fosite.Requester),
		OIDCSessions:   make(map[string]fosite.Requester),
		PKCESessions:   make(map[string]fosite.Requester),
		UsedJTIs:       make(map[string]time.Time),
	}

	// Hash do segredo do cliente usando bcrypt diretamente
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("foobar"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Falha ao gerar hash do segredo do cliente: %v", err)
	}
	// Definição corrigida para my-test-client usando DefaultOpenIDConnectClient
	store.Clients["my-test-client"] = &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "my-test-client",
			Secret:        hashedSecret, // Usa o segredo com hash
			RedirectURIs:  []string{"http://localhost:3000/callback", "http://127.0.0.1:3000/callback"},
			GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token", "client_credentials"},
			ResponseTypes: fosite.Arguments{"code", "token", "id_token", "code id_token", "code token", "id_token token", "code id_token token"},
			Scopes:        fosite.Arguments{"openid", "profile", "email", "offline"},
			Audience:      fosite.Arguments{"https://my-api.com"},
			Public:        false,
		},
		JSONWebKeysURI:          "",
		TokenEndpointAuthMethod: "client_secret_basic",
		RequestURIs:             []string{},
	}

	return store
}

// GetClient recupera um cliente pelo seu ID.
func (s *InMemoryStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	client, ok := s.Clients[id]
	if !ok {
		return nil, fmt.Errorf("%w: Cliente com ID %s não encontrado", fosite.ErrNotFound, id)
	}
	return client, nil
}

// ClientAssertionJWTValid verifica se um ID JWT de asserção de cliente é válido.
func (s *InMemoryStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	if exp, exists := s.UsedJTIs[jti]; exists {
		if time.Now().After(exp) {
			// JTI expirado, trate como desconhecido
			delete(s.UsedJTIs, jti) // Limpa JTI expirado
			return nil
		}
		// JTI existe e não expirou, então já foi usado.
		return fmt.Errorf("%w: JTI %s já foi utilizado", fosite.ErrJTIKnown, jti)
	}
	// JTI não existe, então é válido.
	return nil
}

// SetClientAssertionJWT marca um ID JWT de asserção de cliente como usado.
func (s *InMemoryStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if currentExp, exists := s.UsedJTIs[jti]; exists {
		// Deveria ser detectado por ClientAssertionJWTValid, mas verifica novamente.
		if time.Now().Before(currentExp) {
			return fmt.Errorf("%w: Tentativa de definir JTI já usado %s", fosite.ErrJTIKnown, jti)
		}
	}
	// Armazena o JTI com seu tempo de expiração
	s.UsedJTIs[jti] = exp
	log.Printf("Marcado JTI %s como usado até %v", jti, exp)
	return nil
}

// CreateAuthorizeCodeSession armazena uma sessão de código de autorização.
func (s *InMemoryStore) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.AuthorizeCodes[code] = request
	return nil
}

// GetAuthorizeCodeSession recupera uma sessão de código de autorização.
func (s *InMemoryStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	req, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, fmt.Errorf("%w: Código de autorização não encontrado", fosite.ErrNotFound)
	}
	return req, nil
}

// InvalidateAuthorizeCodeSession marca uma sessão de código de autorização como inválida (usada).
func (s *InMemoryStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.AuthorizeCodes, code)
	return nil
}

// CreateAccessTokenSession armazena uma sessão de token de acesso.
func (s *InMemoryStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.AccessTokens[signature] = request
	return nil
}

// GetAccessTokenSession recupera uma sessão de token de acesso.
func (s *InMemoryStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	req, ok := s.AccessTokens[signature]
	log.Printf("[GetAccessTokenSession] Buscando assinatura: %s. Encontrado? %v", signature, ok)
	if !ok {
		return nil, fmt.Errorf("%w: Token de acesso não encontrado", fosite.ErrNotFound)
	}
	return req, nil
}

// DeleteAccessTokenSession exclui uma sessão de token de acesso.
func (s *InMemoryStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	log.Printf("[DeleteAccessTokenSession] Tentando excluir assinatura: %s. Existe? %v", signature, s.AccessTokens[signature] != nil)
	delete(s.AccessTokens, signature)
	log.Printf("[DeleteAccessTokenSession] Após exclusão para assinatura: %s. Existe? %v", signature, s.AccessTokens[signature] != nil)
	return nil
}

// RevokeAccessToken implementa a lógica de revogação para tokens de acesso.
func (s *InMemoryStore) RevokeAccessToken(ctx context.Context, signature string) error {
	log.Printf("Revogando token de acesso com assinatura: %s", signature)
	return s.DeleteAccessTokenSession(ctx, signature)
}

// -- Métodos para RefreshTokenStorage --

// CreateRefreshTokenSession armazena uma sessão de token de atualização.
func (s *InMemoryStore) CreateRefreshTokenSession(ctx context.Context, signature string, clientID string, request fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if _, ok := s.RefreshTokens[clientID]; !ok {
		s.RefreshTokens[clientID] = make(map[string]fosite.Requester)
	}
	s.RefreshTokens[clientID][signature] = request
	return nil
}

// GetRefreshTokenSession recupera uma sessão de token de atualização pela assinatura.
func (s *InMemoryStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	// Itera por todos os clientes para encontrar a assinatura
	for _, clientTokens := range s.RefreshTokens {
		if req, ok := clientTokens[signature]; ok {
			// Encontrou o requirente associado à assinatura
			return req, nil
		}
	}
	// Assinatura não encontrada em nenhum mapa de tokens do cliente
	return nil, fmt.Errorf("%w: Token de atualização não encontrado para assinatura %s", fosite.ErrNotFound, signature)
}

// DeleteRefreshTokenSession exclui uma sessão de token de atualização pela assinatura.
func (s *InMemoryStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	// Itera por todos os clientes para encontrar e excluir a assinatura
	found := false
	for clientID, clientTokens := range s.RefreshTokens {
		if _, ok := clientTokens[signature]; ok {
			delete(s.RefreshTokens[clientID], signature)
			found = true
			// Limpa o mapa de cliente vazio se necessário (opcional)
			if len(s.RefreshTokens[clientID]) == 0 {
				delete(s.RefreshTokens, clientID)
			}
			break // Assume que a assinatura é única entre os clientes
		}
	}
	if !found {
		log.Printf("Tentativa de excluir assinatura de token de atualização inexistente: %s", signature)
	}
	return nil // Nenhum erro necessário se não for encontrado
}

// RotateRefreshToken implementa a rotação do token de atualização.
func (s *InMemoryStore) RotateRefreshToken(ctx context.Context, signature string, clientID string) error {
	log.Printf("Rotacionando (excluindo) token de atualização com assinatura: %s (para cliente: %s)", signature, clientID)
	return s.DeleteRefreshTokenSession(ctx, signature)
}

// RevokeRefreshToken implementa a lógica de revogação para tokens de atualização.
func (s *InMemoryStore) RevokeRefreshToken(ctx context.Context, signature string) error {
	log.Printf("Revogando token de atualização com assinatura: %s", signature)
	return s.DeleteRefreshTokenSession(ctx, signature)
}

// CreateOpenIDConnectSession armazena uma sessão OIDC.
func (s *InMemoryStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.OIDCSessions[authorizeCode] = request
	return nil
}

// GetOpenIDConnectSession recupera uma sessão OIDC.
func (s *InMemoryStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	req, ok := s.OIDCSessions[authorizeCode]
	if !ok {
		return nil, fmt.Errorf("%w: Sessão OIDC não encontrada para código de autorização %s", fosite.ErrNotFound, authorizeCode)
	}
	return req, nil
}

// DeleteOpenIDConnectSession exclui uma sessão OIDC.
func (s *InMemoryStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.OIDCSessions, authorizeCode)
	return nil
}

// -- Métodos para Armazenamento de Requisições PKCE --

// GetPKCERequestSession recupera uma sessão de requisição PKCE.
func (s *InMemoryStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	req, ok := s.PKCESessions[signature]
	if !ok {
		return nil, fmt.Errorf("%w: Sessão PKCE não encontrada para assinatura %s", fosite.ErrNotFound, signature)
	}
	return req, nil
}

// CreatePKCERequestSession armazena uma sessão de requisição PKCE.
func (s *InMemoryStore) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.PKCESessions[signature] = requester
	return nil
}

// DeletePKCERequestSession exclui uma sessão de requisição PKCE.
func (s *InMemoryStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.PKCESessions, signature)
	return nil
}

// -- Operações CRUD de Client --

// CreateClient implementa o método StorageInterface para criar um cliente
func (s *InMemoryStore) CreateClient(ctx context.Context, client fosite.Client) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.Clients[client.GetID()] = client
	return nil
}

// UpdateClient implementa o método StorageInterface para atualizar um cliente
func (s *InMemoryStore) UpdateClient(ctx context.Context, client fosite.Client) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// Verifica se o cliente existe
	if _, ok := s.Clients[client.GetID()]; !ok {
		return fmt.Errorf("%w: cliente com ID %s não encontrado", fosite.ErrNotFound, client.GetID())
	}

	// Atualiza o cliente
	s.Clients[client.GetID()] = client
	return nil
}

// DeleteClient implementa o método StorageInterface para excluir um cliente
func (s *InMemoryStore) DeleteClient(ctx context.Context, id string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// Verifica se o cliente existe
	if _, ok := s.Clients[id]; !ok {
		return fmt.Errorf("%w: cliente com ID %s não encontrado", fosite.ErrNotFound, id)
	}

	// Exclui o cliente
	delete(s.Clients, id)
	return nil
}

// -- Métodos para Tokens em geral --

// CreateToken implementa o método para criar tokens
func (s *InMemoryStore) CreateToken(ctx context.Context, tokenType string, signature string, clientID string, data interface{}) error {
	// Type assertion para garantir que os dados sejam um fosite.Requester
	requester, ok := data.(fosite.Requester)
	if !ok {
		return fmt.Errorf("tipo de dados inválido para criação de token, esperado fosite.Requester")
	}

	switch tokenType {
	case "access_token":
		return s.CreateAccessTokenSession(ctx, signature, requester)
	case "refresh_token":
		return s.CreateRefreshTokenSession(ctx, signature, clientID, requester)
	case "authorize_code":
		return s.CreateAuthorizeCodeSession(ctx, signature, requester)
	default:
		return fmt.Errorf("tipo de token não suportado: %s", tokenType)
	}
}

// GetToken implementa o método para recuperar tokens
func (s *InMemoryStore) GetToken(ctx context.Context, tokenType string, signature string) (interface{}, error) {
	// Cria uma sessão vazia para recuperação de token
	session := &openid.DefaultSession{}

	var requester fosite.Requester
	var err error

	switch tokenType {
	case "access_token":
		requester, err = s.GetAccessTokenSession(ctx, signature, session)
	case "refresh_token":
		requester, err = s.GetRefreshTokenSession(ctx, signature, session)
	case "authorize_code":
		requester, err = s.GetAuthorizeCodeSession(ctx, signature, session)
	default:
		return nil, fmt.Errorf("tipo de token não suportado: %s", tokenType)
	}

	return requester, err
}

// DeleteToken implementa o método para excluir tokens
func (s *InMemoryStore) DeleteToken(ctx context.Context, tokenType string, signature string) error {
	switch tokenType {
	case "access_token":
		return s.DeleteAccessTokenSession(ctx, signature)
	case "refresh_token":
		return s.DeleteRefreshTokenSession(ctx, signature)
	case "authorize_code":
		return s.InvalidateAuthorizeCodeSession(ctx, signature)
	default:
		return fmt.Errorf("tipo de token não suportado: %s", tokenType)
	}
}

// RevokeToken implementa o método para revogar tokens
func (s *InMemoryStore) RevokeToken(ctx context.Context, tokenType string, signature string) error {
	switch tokenType {
	case "access_token":
		return s.RevokeAccessToken(ctx, signature)
	case "refresh_token":
		return s.RevokeRefreshToken(ctx, signature)
	default:
		return fmt.Errorf("tipo de token não suportado para revogação: %s", tokenType)
	}
}

// -- Métodos para Sessões --

// CreateSession implementa o método para criar sessões
func (s *InMemoryStore) CreateSession(ctx context.Context, sessionType string, id string, data interface{}) error {
	// Type assertion para garantir que os dados sejam um fosite.Requester
	requester, ok := data.(fosite.Requester)
	if !ok {
		return fmt.Errorf("tipo de dados inválido para criação de sessão, esperado fosite.Requester")
	}

	switch sessionType {
	case "openid":
		return s.CreateOpenIDConnectSession(ctx, id, requester)
	case "pkce":
		return s.CreatePKCERequestSession(ctx, id, requester)
	default:
		return fmt.Errorf("tipo de sessão não suportado: %s", sessionType)
	}
}

// GetSession implementa o método para recuperar sessões
func (s *InMemoryStore) GetSession(ctx context.Context, sessionType string, id string) (interface{}, error) {
	// Cria uma sessão vazia para recuperação de sessão
	session := &openid.DefaultSession{}

	switch sessionType {
	case "openid":
		// Para GetOpenIDConnectSession, precisamos de um requester fake
		dummyRequester := &fosite.Request{Session: session}
		return s.GetOpenIDConnectSession(ctx, id, dummyRequester)
	case "pkce":
		return s.GetPKCERequestSession(ctx, id, session)
	default:
		return nil, fmt.Errorf("tipo de sessão não suportado: %s", sessionType)
	}
}

// DeleteSession implementa o método para excluir sessões
func (s *InMemoryStore) DeleteSession(ctx context.Context, sessionType string, id string) error {
	switch sessionType {
	case "openid":
		return s.DeleteOpenIDConnectSession(ctx, id)
	case "pkce":
		return s.DeletePKCERequestSession(ctx, id)
	default:
		return fmt.Errorf("tipo de sessão não suportado: %s", sessionType)
	}
}

// ValidateJWT implementa o método para validar JWTs
func (s *InMemoryStore) ValidateJWT(ctx context.Context, jti string) error {
	return s.ClientAssertionJWTValid(ctx, jti)
}

// MarkJWTAsUsed implementa o método para marcar JWTs como usados
func (s *InMemoryStore) MarkJWTAsUsed(ctx context.Context, jti string, exp time.Time) error {
	return s.SetClientAssertionJWT(ctx, jti, exp)
}
