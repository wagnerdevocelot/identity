package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
)

// For this example, we use an in-memory store.
// In a real-world application, you would use a persistent store (e.g., SQL database).
var store = NewInMemoryStore()

// Fosite configuration using fosite.Config for v0.49.0+
var fositeConfig = &fosite.Config{
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

// JWT signing secret (32 bytes)
var jwtSecret = []byte("some-random-secret-key-32-bytes!")

// RSA Private key for signing JWTs (ID Tokens)
var privateKey *rsa.PrivateKey

// Declare provider variable globally
var oauth2Provider fosite.OAuth2Provider // Revert to interface type

// init function: Use compose.Compose again
func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Initialize the provider using compose.Compose
	oauth2Provider = compose.Compose(
		fositeConfig,
		store,
		// Configure strategies using CommonStrategy
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(fositeConfig),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(func(ctx context.Context) (interface{}, error) { return privateKey, nil }, fositeConfig),
		},

		// List of Enabled Handler Factories:
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory, // Keep enabled for now
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory, // Re-enabled
		compose.OAuth2TokenRevocationFactory,    // Re-enabled

		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectImplicitFactory,
		compose.OpenIDConnectHybridFactory,
		compose.OpenIDConnectRefreshFactory,

		compose.OAuth2PKCEFactory,
	)
	log.Println("Reverted to compose.Compose setup.")
}

// setupRouter configures and returns the main HTTP handler
func setupRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/auth", authEndpoint)
	mux.HandleFunc("/oauth2/token", tokenEndpoint)
	mux.HandleFunc("/oauth2/introspect", introspectionEndpoint)
	mux.HandleFunc("/oauth2/revoke", revocationEndpoint)
	// mux.HandleFunc("/.well-known/openid-configuration", wellKnownOpenIDConfigurationHandler) // Commented out
	// mux.HandleFunc("/.well-known/jwks.json", jwksHandler) // Commented out

	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/consent", consentHandler)
	return mux
}

func main() {
	router := setupRouter()
	log.Println("Starting OAuth2 server on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatalf("Could not start server: %s\n", err.Error())
	}
}

// Placeholder for JWKS URI - Fosite needs this for OIDC - REMOVED
/*
func jwksFetcherStrategy(provider fosite.OAuth2Provider) *openid.DefaultStrategy {
	return &openid.DefaultStrategy{
		JWTStrategy: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return jwtSecret, nil // Using symmetric key for simplicity, RSA/ECDSA recommended for production
			},
		},
		// In a real scenario, you would fetch JWKS from a dedicated endpoint.
		// For this example, we are using the symmetric key directly.
	}
}
*/

// Initialize OIDC strategy (needed by ComposeAllEnabled) - REMOVED
/*
func init() {
	// Adjust the Fosite provider composition if necessary, especially if OIDC is needed.
	// The compose.ComposeAllEnabled includes OIDC, which requires a JWT strategy.
	// If you don't need OIDC, you might use a different composer function.

	// A simple way to satisfy OIDC dependencies for ComposeAllEnabled.
	// In a real app, configure OIDC properly, likely with asymmetric keys and a JWKS endpoint.
	oauth2Provider.OpenIDConnectRequestValidator = openid.NewOpenIDConnectRequestValidator(
		&jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return jwtSecret, nil
			},
		},
		oauth2Provider.Hasher,
	)
}
*/

// introspectionEndpoint handles token introspection requests
func introspectionEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()                    // Use request context directly
	session := new(openid.DefaultSession) // Use appropriate session type
	ir, err := oauth2Provider.NewIntrospectionRequest(ctx, r, session)
	if err != nil {
		log.Printf("Introspection request failed: %+v", err)
		oauth2Provider.WriteIntrospectionError(ctx, w, err) // Add ctx
		return
	}
	oauth2Provider.WriteIntrospectionResponse(ctx, w, ir) // Add ctx
}

// revocationEndpoint handles token revocation requests
func revocationEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context() // Use request context directly
	err := oauth2Provider.NewRevocationRequest(ctx, r)
	if err != nil {
		log.Printf("Revocation request failed: %+v", err)
	}
	oauth2Provider.WriteRevocationResponse(ctx, w, err) // Add ctx
}

/* Commented out wellKnownOpenIDConfigurationHandler
// wellKnownOpenIDConfigurationHandler serves OIDC discovery information
func wellKnownOpenIDConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	issuer := "http://localhost:8080"
	jwksURI := issuer + "/.well-known/jwks.json"

	// Use openid.DiscoveryMetadata for v0.49.0+ OIDC discovery - THIS IS UNDEFINED
	config := openid.DiscoveryMetadata{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oauth2/auth",
		TokenEndpoint:         issuer + "/oauth2/token",
		JwksURI:               jwksURI,
		IntrospectionEndpoint: issuer + "/oauth2/introspect",
		RevocationEndpoint:    issuer + "/oauth2/revoke",
		SubjectTypesSupported: []string{"public"},
		ResponseTypesSupported: []string{
			"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token",
		},
		GrantTypesSupported: []string{
			"authorization_code", "implicit", "refresh_token", "client_credentials",
		},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email", "offline"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported:                 []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "picture"},
		CodeChallengeMethodsSupported:   []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}
*/

/* Commented out jwksHandler
// jwksHandler serves the JSON Web Key Set (JWKS)
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	// Use PublicKeyToJWKS from compose package - THIS IS UNDEFINED
	// Need to replace with go-jose or similar JWK generation
	jwkSet, err := compose.PublicKeyToJWKS(&privateKey.PublicKey, "sig")
	if err != nil {
		http.Error(w, "Failed to create JWK Set", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwkSet)
}
*/
