package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"golang.org/x/crypto/bcrypt"
)

// StorageInterface defines a generic contract for all storage implementations,
// providing a common set of methods for CRUD operations on different entities.
type StorageInterface interface {
	// Client operations
	GetClient(ctx context.Context, id string) (fosite.Client, error)
	CreateClient(ctx context.Context, client fosite.Client) error
	UpdateClient(ctx context.Context, client fosite.Client) error
	DeleteClient(ctx context.Context, id string) error

	// Token operations
	CreateToken(ctx context.Context, tokenType string, signature string, clientID string, data interface{}) error
	GetToken(ctx context.Context, tokenType string, signature string) (interface{}, error)
	DeleteToken(ctx context.Context, tokenType string, signature string) error
	RevokeToken(ctx context.Context, tokenType string, signature string) error

	// Session operations
	CreateSession(ctx context.Context, sessionType string, id string, data interface{}) error
	GetSession(ctx context.Context, sessionType string, id string) (interface{}, error)
	DeleteSession(ctx context.Context, sessionType string, id string) error

	// JWT operations
	ValidateJWT(ctx context.Context, jti string) error
	MarkJWTAsUsed(ctx context.Context, jti string, exp time.Time) error
}

// InMemoryStore provides a simple in-memory implementation of Fosite's storage interfaces.
// WARNING: This is for demonstration purposes only. Use a persistent store in production.
type InMemoryStore struct {
	Clients        map[string]fosite.Client
	AuthorizeCodes map[string]fosite.Requester
	AccessTokens   map[string]fosite.Requester
	RefreshTokens  map[string]map[string]fosite.Requester
	OIDCSessions   map[string]fosite.Requester
	PKCESessions   map[string]fosite.Requester // Added for PKCE
	Mutex          sync.RWMutex
	UsedJTIs       map[string]time.Time
}

// NewInMemoryStore initializes a new in-memory store.
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

	// Hash the client secret using bcrypt directly
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("foobar"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash client secret: %v", err)
	}
	// Corrected definition for my-test-client using DefaultOpenIDConnectClient
	store.Clients["my-test-client"] = &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "my-test-client",
			Secret:        hashedSecret, // Use the hashed secret
			RedirectURIs:  []string{"http://localhost:3000/callback", "http://127.0.0.1:3000/callback"},
			GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token", "client_credentials"},
			ResponseTypes: fosite.Arguments{"code", "token", "id_token", "code id_token", "code token", "id_token token", "code id_token token"},
			Scopes:        fosite.Arguments{"openid", "profile", "email", "offline"},
			Audience:      fosite.Arguments{"https://my-api.com"},
			Public:        false,
		},
		// Kept valid OIDC fields, removed invalid ones for v0.49.0
		JSONWebKeysURI:          "",
		TokenEndpointAuthMethod: "client_secret_basic",
		RequestURIs:             []string{},
		// BackChannelLogoutSessionRequired: false, // Removed
		// Contacts:                       []string{"admin@example.com"}, // Removed
	}

	return store
}

// GetClient retrieves a client by its ID.
func (s *InMemoryStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	client, ok := s.Clients[id]
	if !ok {
		return nil, fmt.Errorf("%w: Client with ID %s not found", fosite.ErrNotFound, id)
	}
	return client, nil
}

// ClientAssertionJWTValid checks if a client assertion JWT ID is valid (basic stub).
// Renamed from IsClientAssertionJWTValid
func (s *InMemoryStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	if exp, exists := s.UsedJTIs[jti]; exists {
		if time.Now().After(exp) {
			// JTI expired, treat as unknown
			delete(s.UsedJTIs, jti) // Clean up expired JTI
			return nil
		}
		// JTI exists and hasn't expired, so it's been used.
		return fmt.Errorf("%w: JTI %s has already been used", fosite.ErrJTIKnown, jti)
	}
	// JTI doesn't exist, so it's valid.
	return nil
}

// SetClientAssertionJWT marks a client assertion JWT ID as used (basic stub).
// Renamed from SetClientAssertionJWTMarkedAsUsed and updated signature
func (s *InMemoryStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if currentExp, exists := s.UsedJTIs[jti]; exists {
		// Should be caught by ClientAssertionJWTValid, but check again.
		if time.Now().Before(currentExp) {
			return fmt.Errorf("%w: Attempted to set already used JTI %s", fosite.ErrJTIKnown, jti)
		}
	}
	// Store the JTI with its expiration time
	s.UsedJTIs[jti] = exp
	log.Printf("Marked JTI %s as used until %v", jti, exp)
	return nil
}

// CreateAuthorizeCodeSession stores an authorization code session.
func (s *InMemoryStore) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.AuthorizeCodes[code] = request
	return nil
}

// GetAuthorizeCodeSession retrieves an authorization code session.
func (s *InMemoryStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	req, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, fmt.Errorf("%w: Authorization code not found", fosite.ErrNotFound)
	}
	// Note: Fosite expects the session to be hydrated here if necessary.
	// Since we store the full requester, we might not need to do much with the session parameter.
	return req, nil
}

// InvalidateAuthorizeCodeSession marks an authorization code session as invalid (used).
func (s *InMemoryStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.AuthorizeCodes, code)
	return nil
}

// CreateAccessTokenSession stores an access token session.
func (s *InMemoryStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.AccessTokens[signature] = request
	return nil
}

// GetAccessTokenSession retrieves an access token session.
func (s *InMemoryStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	req, ok := s.AccessTokens[signature]
	log.Printf("[GetAccessTokenSession] Looking up signature: %s. Found? %v", signature, ok)
	if !ok {
		return nil, fmt.Errorf("%w: Access token not found", fosite.ErrNotFound)
	}
	return req, nil
}

// DeleteAccessTokenSession deletes an access token session.
func (s *InMemoryStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	log.Printf("[DeleteAccessTokenSession] Attempting to delete signature: %s. Exists? %v", signature, s.AccessTokens[signature] != nil)
	delete(s.AccessTokens, signature)
	log.Printf("[DeleteAccessTokenSession] After delete for signature: %s. Exists? %v", signature, s.AccessTokens[signature] != nil)
	return nil
}

// RevokeAccessToken implements the revocation logic for access tokens.
// For this simple store, it just deletes the token.
func (s *InMemoryStore) RevokeAccessToken(ctx context.Context, signature string) error {
	log.Printf("Revoking access token with signature: %s", signature)
	return s.DeleteAccessTokenSession(ctx, signature)
}

// -- RefreshTokenStorage Methods --

// CreateRefreshTokenSession stores a refresh token session, keyed by client ID then signature.
func (s *InMemoryStore) CreateRefreshTokenSession(ctx context.Context, signature string, clientID string, request fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if _, ok := s.RefreshTokens[clientID]; !ok {
		s.RefreshTokens[clientID] = make(map[string]fosite.Requester)
	}
	s.RefreshTokens[clientID][signature] = request
	return nil
}

// GetRefreshTokenSession retrieves a refresh token session by signature.
func (s *InMemoryStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	// Iterate through all clients to find the signature
	for _, clientTokens := range s.RefreshTokens {
		if req, ok := clientTokens[signature]; ok {
			// Found the requester associated with the signature
			return req, nil
		}
	}
	// Signature not found in any client's token map
	return nil, fmt.Errorf("%w: Refresh token not found for signature %s", fosite.ErrNotFound, signature)
}

// DeleteRefreshTokenSession deletes a refresh token session by signature.
func (s *InMemoryStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	// Iterate through all clients to find and delete the signature
	found := false
	for clientID, clientTokens := range s.RefreshTokens {
		if _, ok := clientTokens[signature]; ok {
			delete(s.RefreshTokens[clientID], signature)
			found = true
			// Clean up empty client map if necessary (optional)
			if len(s.RefreshTokens[clientID]) == 0 {
				delete(s.RefreshTokens, clientID)
			}
			break // Assume signature is unique across clients
		}
	}
	if !found {
		log.Printf("Attempted to delete non-existent refresh token signature: %s", signature)
	}
	return nil // No error required if not found
}

// RotateRefreshToken implements the refresh token rotation.
// For this simple store, it just deletes the old token.
// Added clientID argument to match oauth2.CoreStorage interface.
func (s *InMemoryStore) RotateRefreshToken(ctx context.Context, signature string, clientID string) error {
	// Note: clientID is not strictly needed for deletion logic here as DeleteRefreshTokenSession iterates,
	// but it's required by the interface signature.
	log.Printf("Rotating (deleting) refresh token with signature: %s (for client: %s - though clientID is ignored in delete logic)", signature, clientID)
	return s.DeleteRefreshTokenSession(ctx, signature)
}

// RevokeRefreshToken implements the revocation logic for refresh tokens.
// For this simple store, it just deletes the token.
func (s *InMemoryStore) RevokeRefreshToken(ctx context.Context, signature string) error {
	log.Printf("Revoking refresh token with signature: %s", signature)
	return s.DeleteRefreshTokenSession(ctx, signature)
}

// CreateOpenIDConnectSession stores an OIDC session.
func (s *InMemoryStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.OIDCSessions[authorizeCode] = request
	return nil
}

// GetOpenIDConnectSession retrieves an OIDC session.
func (s *InMemoryStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	req, ok := s.OIDCSessions[authorizeCode]
	if !ok {
		return nil, fmt.Errorf("%w: OIDC session not found for authorize code %s", fosite.ErrNotFound, authorizeCode)
	}
	// Potentially hydrate the requester passed in?
	// Check Fosite docs/examples for exact behavior expected.
	return req, nil
}

// DeleteOpenIDConnectSession deletes an OIDC session.
func (s *InMemoryStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.OIDCSessions, authorizeCode)
	return nil
}

// -- PKCE Request Storage Methods --

// GetPKCERequestSession retrieves a PKCE request session.
func (s *InMemoryStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.Mutex.RLock()
	defer s.Mutex.RUnlock()
	req, ok := s.PKCESessions[signature]
	if !ok {
		return nil, fmt.Errorf("%w: PKCE session not found for signature %s", fosite.ErrNotFound, signature)
	}
	return req, nil
}

// CreatePKCERequestSession stores a PKCE request session.
func (s *InMemoryStore) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.PKCESessions[signature] = requester
	return nil
}

// DeletePKCERequestSession deletes a PKCE request session.
func (s *InMemoryStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	delete(s.PKCESessions, signature)
	return nil
}

// -- StorageInterface Implementation --

// CreateClient implements the StorageInterface method for creating a client
func (s *InMemoryStore) CreateClient(ctx context.Context, client fosite.Client) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	s.Clients[client.GetID()] = client
	return nil
}

// UpdateClient implements the StorageInterface method for updating a client
func (s *InMemoryStore) UpdateClient(ctx context.Context, client fosite.Client) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// Verify client exists
	if _, ok := s.Clients[client.GetID()]; !ok {
		return fmt.Errorf("%w: client with ID %s not found", fosite.ErrNotFound, client.GetID())
	}

	// Update client
	s.Clients[client.GetID()] = client
	return nil
}

// DeleteClient implements the StorageInterface method for deleting a client
func (s *InMemoryStore) DeleteClient(ctx context.Context, id string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// Check if client exists
	if _, ok := s.Clients[id]; !ok {
		return fmt.Errorf("%w: client with ID %s not found", fosite.ErrNotFound, id)
	}

	// Delete client
	delete(s.Clients, id)
	return nil
}

// CreateToken implements the StorageInterface method for creating tokens
func (s *InMemoryStore) CreateToken(ctx context.Context, tokenType string, signature string, clientID string, data interface{}) error {
	// Type assertion to ensure data is a fosite.Requester
	requester, ok := data.(fosite.Requester)
	if !ok {
		return fmt.Errorf("invalid data type for token creation, expected fosite.Requester")
	}

	switch tokenType {
	case "access_token":
		return s.CreateAccessTokenSession(ctx, signature, requester)
	case "refresh_token":
		return s.CreateRefreshTokenSession(ctx, signature, clientID, requester)
	case "authorize_code":
		return s.CreateAuthorizeCodeSession(ctx, signature, requester)
	default:
		return fmt.Errorf("unsupported token type: %s", tokenType)
	}
}

// GetToken implements the StorageInterface method for retrieving tokens
func (s *InMemoryStore) GetToken(ctx context.Context, tokenType string, signature string) (interface{}, error) {
	// Create an empty session for token retrieval
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
		return nil, fmt.Errorf("unsupported token type: %s", tokenType)
	}

	return requester, err
}

// DeleteToken implements the StorageInterface method for deleting tokens
func (s *InMemoryStore) DeleteToken(ctx context.Context, tokenType string, signature string) error {
	switch tokenType {
	case "access_token":
		return s.DeleteAccessTokenSession(ctx, signature)
	case "refresh_token":
		return s.DeleteRefreshTokenSession(ctx, signature)
	case "authorize_code":
		return s.InvalidateAuthorizeCodeSession(ctx, signature)
	default:
		return fmt.Errorf("unsupported token type: %s", tokenType)
	}
}

// RevokeToken implements the StorageInterface method for revoking tokens
func (s *InMemoryStore) RevokeToken(ctx context.Context, tokenType string, signature string) error {
	switch tokenType {
	case "access_token":
		return s.RevokeAccessToken(ctx, signature)
	case "refresh_token":
		return s.RevokeRefreshToken(ctx, signature)
	default:
		return fmt.Errorf("unsupported token type for revocation: %s", tokenType)
	}
}

// CreateSession implements the StorageInterface method for creating sessions
func (s *InMemoryStore) CreateSession(ctx context.Context, sessionType string, id string, data interface{}) error {
	// Type assertion to ensure data is a fosite.Requester
	requester, ok := data.(fosite.Requester)
	if !ok {
		return fmt.Errorf("invalid data type for session creation, expected fosite.Requester")
	}

	switch sessionType {
	case "openid":
		return s.CreateOpenIDConnectSession(ctx, id, requester)
	case "pkce":
		return s.CreatePKCERequestSession(ctx, id, requester)
	default:
		return fmt.Errorf("unsupported session type: %s", sessionType)
	}
}

// GetSession implements the StorageInterface method for retrieving sessions
func (s *InMemoryStore) GetSession(ctx context.Context, sessionType string, id string) (interface{}, error) {
	// Create an empty session for session retrieval
	session := &openid.DefaultSession{}

	switch sessionType {
	case "openid":
		// For GetOpenIDConnectSession, we need a dummy requester
		dummyRequester := &fosite.Request{Session: session}
		return s.GetOpenIDConnectSession(ctx, id, dummyRequester)
	case "pkce":
		return s.GetPKCERequestSession(ctx, id, session)
	default:
		return nil, fmt.Errorf("unsupported session type: %s", sessionType)
	}
}

// DeleteSession implements the StorageInterface method for deleting sessions
func (s *InMemoryStore) DeleteSession(ctx context.Context, sessionType string, id string) error {
	switch sessionType {
	case "openid":
		return s.DeleteOpenIDConnectSession(ctx, id)
	case "pkce":
		return s.DeletePKCERequestSession(ctx, id)
	default:
		return fmt.Errorf("unsupported session type: %s", sessionType)
	}
}

// ValidateJWT implements the StorageInterface method for validating JWTs
func (s *InMemoryStore) ValidateJWT(ctx context.Context, jti string) error {
	return s.ClientAssertionJWTValid(ctx, jti)
}

// MarkJWTAsUsed implements the StorageInterface method for marking JWTs as used
func (s *InMemoryStore) MarkJWTAsUsed(ctx context.Context, jti string, exp time.Time) error {
	return s.SetClientAssertionJWT(ctx, jti, exp)
}

// Ensure InMemoryStore implements all required interfaces
var (
	_ fosite.Storage                     = (*InMemoryStore)(nil)
	_ fosite.ClientManager               = (*InMemoryStore)(nil)
	_ openid.OpenIDConnectRequestStorage = (*InMemoryStore)(nil)
	_ oauth2.CoreStorage                 = (*InMemoryStore)(nil)
	_ oauth2.TokenRevocationStorage      = (*InMemoryStore)(nil)
	_ StorageInterface                   = (*InMemoryStore)(nil) // Ensure our store implements our generic interface
)
