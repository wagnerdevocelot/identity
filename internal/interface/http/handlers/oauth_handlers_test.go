package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockOAuth2Provider implementa fosite.OAuth2Provider para fins de teste
type MockOAuth2Provider struct {
	mock.Mock
}

func (m *MockOAuth2Provider) NewAuthorizeRequest(ctx context.Context, r *http.Request) (fosite.AuthorizeRequester, error) {
	args := m.Called(ctx, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(fosite.AuthorizeRequester), args.Error(1)
}

func (m *MockOAuth2Provider) NewPushedAuthorizeRequest(ctx context.Context, r *http.Request) (fosite.AuthorizeRequester, error) {
	args := m.Called(ctx, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(fosite.AuthorizeRequester), args.Error(1)
}

func (m *MockOAuth2Provider) NewAuthorizeResponse(ctx context.Context, ar fosite.AuthorizeRequester, session fosite.Session) (fosite.AuthorizeResponder, error) {
	args := m.Called(ctx, ar, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(fosite.AuthorizeResponder), args.Error(1)
}

func (m *MockOAuth2Provider) NewPushedAuthorizeResponse(ctx context.Context, ar fosite.AuthorizeRequester, session fosite.Session) (fosite.PushedAuthorizeResponder, error) {
	args := m.Called(ctx, ar, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(fosite.PushedAuthorizeResponder), args.Error(1)
}

func (m *MockOAuth2Provider) WriteAuthorizeResponse(ctx context.Context, w http.ResponseWriter, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) {
	m.Called(ctx, w, ar, resp)
}

func (m *MockOAuth2Provider) WritePushedAuthorizeResponse(ctx context.Context, rw http.ResponseWriter, ar fosite.AuthorizeRequester, resp fosite.PushedAuthorizeResponder) {
	m.Called(ctx, rw, ar, resp)
}

func (m *MockOAuth2Provider) WriteAuthorizeError(ctx context.Context, w http.ResponseWriter, ar fosite.AuthorizeRequester, err error) {
	m.Called(ctx, w, ar, err)
}

func (m *MockOAuth2Provider) WritePushedAuthorizeError(ctx context.Context, rw http.ResponseWriter, ar fosite.AuthorizeRequester, err error) {
	m.Called(ctx, rw, ar, err)
}

func (m *MockOAuth2Provider) NewAccessRequest(ctx context.Context, r *http.Request, session fosite.Session) (fosite.AccessRequester, error) {
	args := m.Called(ctx, r, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(fosite.AccessRequester), args.Error(1)
}

func (m *MockOAuth2Provider) NewAccessResponse(ctx context.Context, ar fosite.AccessRequester) (fosite.AccessResponder, error) {
	args := m.Called(ctx, ar)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(fosite.AccessResponder), args.Error(1)
}

func (m *MockOAuth2Provider) WriteAccessResponse(ctx context.Context, w http.ResponseWriter, ar fosite.AccessRequester, resp fosite.AccessResponder) {
	m.Called(ctx, w, ar, resp)
}

func (m *MockOAuth2Provider) WriteAccessError(ctx context.Context, w http.ResponseWriter, ar fosite.AccessRequester, err error) {
	m.Called(ctx, w, ar, err)
}

func (m *MockOAuth2Provider) NewRevocationRequest(ctx context.Context, r *http.Request) error {
	args := m.Called(ctx, r)
	return args.Error(0)
}

func (m *MockOAuth2Provider) WriteRevocationResponse(ctx context.Context, w http.ResponseWriter, err error) {
	m.Called(ctx, w, err)
}

func (m *MockOAuth2Provider) IntrospectToken(ctx context.Context, token string, tokenType fosite.TokenType, session fosite.Session, scope ...string) (fosite.TokenType, fosite.AccessRequester, error) {
	args := m.Called(ctx, token, tokenType, session, scope)
	if args.Get(1) == nil {
		return args.Get(0).(fosite.TokenType), nil, args.Error(2)
	}
	return args.Get(0).(fosite.TokenType), args.Get(1).(fosite.AccessRequester), args.Error(2)
}

func (m *MockOAuth2Provider) NewIntrospectionRequest(ctx context.Context, r *http.Request, session fosite.Session) (fosite.IntrospectionResponder, error) {
	args := m.Called(ctx, r, session)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(fosite.IntrospectionResponder), args.Error(1)
}

func (m *MockOAuth2Provider) WriteIntrospectionResponse(ctx context.Context, w http.ResponseWriter, r fosite.IntrospectionResponder) {
	m.Called(ctx, w, r)
}

func (m *MockOAuth2Provider) WriteIntrospectionError(ctx context.Context, w http.ResponseWriter, err error) {
	m.Called(ctx, w, err)
}

// MockAuthorizeRequest implementa fosite.AuthorizeRequester para fins de teste
type MockAuthorizeRequest struct {
	mock.Mock
}

func (m *MockAuthorizeRequest) GetResponseTypes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAuthorizeRequest) GetClient() fosite.Client {
	args := m.Called()
	return args.Get(0).(fosite.Client)
}

func (m *MockAuthorizeRequest) GetRequestedScopes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAuthorizeRequest) GetRequestedAudience() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAuthorizeRequest) GetRedirectURI() *url.URL {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*url.URL)
}

func (m *MockAuthorizeRequest) GetState() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizeRequest) GetSession() fosite.Session {
	args := m.Called()
	return args.Get(0).(fosite.Session)
}

func (m *MockAuthorizeRequest) SetSession(session fosite.Session) {
	m.Called(session)
}

func (m *MockAuthorizeRequest) GetRequestForm() url.Values {
	args := m.Called()
	return args.Get(0).(url.Values)
}

func (m *MockAuthorizeRequest) Merge(requester fosite.Requester) {
	m.Called(requester)
}

func (m *MockAuthorizeRequest) GrantScope(scope string) {
	m.Called(scope)
}

func (m *MockAuthorizeRequest) GetGrantedScopes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAuthorizeRequest) GrantAudience(audience string) {
	m.Called(audience)
}

func (m *MockAuthorizeRequest) GetGrantedAudience() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAuthorizeRequest) SetID(id string) {
	m.Called(id)
}

func (m *MockAuthorizeRequest) GetID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizeRequest) AppendRequestedScope(scope string) {
	m.Called(scope)
}

func (m *MockAuthorizeRequest) DidHandleAllResponseTypes() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockAuthorizeRequest) GetDefaultResponseMode() fosite.ResponseModeType {
	args := m.Called()
	return args.Get(0).(fosite.ResponseModeType)
}

func (m *MockAuthorizeRequest) GetRequestedAt() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

func (m *MockAuthorizeRequest) GetResponseMode() fosite.ResponseModeType {
	args := m.Called()
	return args.Get(0).(fosite.ResponseModeType)
}

func (m *MockAuthorizeRequest) IsRedirectURIValid() bool {
	args := m.Called()
	return args.Bool(0)
}

// MockAuthorizeResponse implementa fosite.AuthorizeResponder para fins de teste
type MockAuthorizeResponse struct {
	mock.Mock
}

func (m *MockAuthorizeResponse) GetCode() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAuthorizeResponse) GetHeader() http.Header {
	args := m.Called()
	return args.Get(0).(http.Header)
}

func (m *MockAuthorizeResponse) AddHeader(key, value string) {
	m.Called(key, value)
}

func (m *MockAuthorizeResponse) GetParameters() url.Values {
	args := m.Called()
	return args.Get(0).(url.Values)
}

func (m *MockAuthorizeResponse) AddParameter(key, value string) {
	m.Called(key, value)
}

// MockClientManager implementa fosite.ClientManager para fins de teste
type MockClientManager struct {
	mock.Mock
}

func (m *MockClientManager) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(fosite.Client), args.Error(1)
}

// MockClient implementa fosite.Client para fins de teste
type MockClient struct {
	mock.Mock
}

func (m *MockClient) GetID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockClient) GetRedirectURIs() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockClient) GetHashedSecret() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

func (m *MockClient) GetScopes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockClient) GetGrantTypes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockClient) GetResponseTypes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockClient) GetAudience() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockClient) IsPublic() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockClient) GetRequestURIs() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

// MockAccessRequest implementa fosite.AccessRequester para fins de teste
type MockAccessRequest struct {
	mock.Mock
}

func (m *MockAccessRequest) GetGrantTypes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAccessRequest) GetClient() fosite.Client {
	args := m.Called()
	return args.Get(0).(fosite.Client)
}

func (m *MockAccessRequest) GetRequestedScopes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAccessRequest) GetRequestedAudience() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAccessRequest) GetRedirectURI() *url.URL {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*url.URL)
}

func (m *MockAccessRequest) GetState() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAccessRequest) GetSession() fosite.Session {
	args := m.Called()
	return args.Get(0).(fosite.Session)
}

func (m *MockAccessRequest) SetSession(session fosite.Session) {
	m.Called(session)
}

func (m *MockAccessRequest) GetRequestForm() url.Values {
	args := m.Called()
	return args.Get(0).(url.Values)
}

func (m *MockAccessRequest) Merge(requester fosite.Requester) {
	m.Called(requester)
}

func (m *MockAccessRequest) GrantScope(scope string) {
	m.Called(scope)
}

func (m *MockAccessRequest) GetGrantedScopes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAccessRequest) GrantAudience(audience string) {
	m.Called(audience)
}

func (m *MockAccessRequest) GetGrantedAudience() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAccessRequest) SetID(id string) {
	m.Called(id)
}

func (m *MockAccessRequest) GetID() string {
	args := m.Called()
	return args.String(0)
}

// MockAccessResponse implementa fosite.AccessResponder para fins de teste
type MockAccessResponse struct {
	mock.Mock
}

func (m *MockAccessResponse) GetExtra(key string) interface{} {
	args := m.Called(key)
	return args.Get(0)
}

func (m *MockAccessResponse) SetExtra(key string, value interface{}) {
	m.Called(key, value)
}

func (m *MockAccessResponse) GetAccessToken() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAccessResponse) GetTokenType() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAccessResponse) GetExpiresIn() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func (m *MockAccessResponse) GetScopes() fosite.Arguments {
	args := m.Called()
	return args.Get(0).(fosite.Arguments)
}

func (m *MockAccessResponse) ToMap() map[string]interface{} {
	args := m.Called()
	return args.Get(0).(map[string]interface{})
}

// MockIntrospectionResponse implementa fosite.IntrospectionResponder para fins de teste
type MockIntrospectionResponse struct {
	mock.Mock
}

func (m *MockIntrospectionResponse) ToMap() map[string]interface{} {
	args := m.Called()
	return args.Get(0).(map[string]interface{})
}

func (m *MockIntrospectionResponse) GetAccessRequester() fosite.AccessRequester {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(fosite.AccessRequester)
}

// TestAuthEndpoint_NoAuthentication testa o redirecionamento para login quando o usuário não está autenticado
func TestAuthEndpoint_NoAuthentication(t *testing.T) {
	// Configurar o mock do OAuth2Provider
	provider := new(MockOAuth2Provider)

	// Criar um mock de AuthorizeRequest
	authRequest := new(MockAuthorizeRequest)

	// Configurar expectativas para o mock
	provider.On("NewAuthorizeRequest", mock.Anything, mock.Anything).Return(authRequest, nil)
	// Adicionar expectativa para IntrospectToken
	provider.On("IntrospectToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(fosite.TokenType(""), nil, nil)

	// Criar o handler OAuth2 com o mock de provider
	handler := &OAuth2Handler{
		Provider:  provider,
		Sessions:  make(map[string]*Session),
		Templates: nil, // Não precisamos de templates para este teste
	}

	// Criar uma requisição HTTP de teste
	req := httptest.NewRequest("GET", "/oauth2/auth?client_id=client123&response_type=code&scope=openid&redirect_uri=http://localhost/callback", nil)
	rr := httptest.NewRecorder()

	// Executar o handler
	handler.AuthEndpoint(rr, req)

	// Verificar o resultado
	assert.Equal(t, http.StatusFound, rr.Code, "Deve redirecionar para a página de login")

	// Verificar se o redirecionamento é para a página de login
	location := rr.Header().Get("Location")
	assert.Contains(t, location, "/login", "Deve redirecionar para a página de login")
	assert.Contains(t, location, "session_id=", "Deve incluir um ID de sessão")

	// Verificar se uma sessão foi criada
	assert.Equal(t, 1, len(handler.Sessions), "Deve existir uma sessão criada")

	// Verificar se o redirecionamento contém o ID da sessão correta
	sessionID := strings.TrimPrefix(location, "/login?session_id=")
	_, exists := handler.Sessions[sessionID]
	assert.True(t, exists, "A sessão com o ID fornecido deve existir")

	// Verificar se todos os métodos do mock foram chamados corretamente
	provider.AssertExpectations(t)
	authRequest.AssertExpectations(t)
}

// TestTokenEndpoint_Success testa uma requisição bem-sucedida ao endpoint de token
func TestTokenEndpoint_Success(t *testing.T) {
	// Configurar o mock do OAuth2Provider
	provider := new(MockOAuth2Provider)

	// Criar mocks para AccessRequest e AccessResponse
	accessRequest := new(MockAccessRequest)
	accessResponse := new(MockAccessResponse)

	// Configurar respostas do token
	tokenResponse := map[string]interface{}{
		"access_token":  "test_access_token",
		"token_type":    "bearer",
		"expires_in":    3600,
		"scope":         "openid profile",
		"refresh_token": "test_refresh_token",
	}

	// Configurar expectativas para o mock
	provider.On("NewAccessRequest", mock.Anything, mock.Anything, mock.Anything).Return(accessRequest, nil)
	provider.On("NewAccessResponse", mock.Anything, accessRequest).Return(accessResponse, nil)
	provider.On("WriteAccessResponse", mock.Anything, mock.Anything, accessRequest, accessResponse).Run(func(args mock.Arguments) {
		resp := args.Get(1).(http.ResponseWriter)
		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		json.NewEncoder(resp).Encode(tokenResponse)
	})
	// Adicionar expectativa para IntrospectToken
	provider.On("IntrospectToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(fosite.TokenType(""), nil, nil)

	// Criar o handler OAuth2 com o mock de provider
	handler := &OAuth2Handler{
		Provider:  provider,
		Sessions:  make(map[string]*Session),
		Templates: nil, // Não precisamos de templates para este teste
	}

	// Criar uma requisição HTTP de teste
	formData := url.Values{}
	formData.Add("grant_type", "authorization_code")
	formData.Add("code", "test_code")
	formData.Add("client_id", "client123")
	formData.Add("client_secret", "secret456")
	formData.Add("redirect_uri", "http://localhost/callback")

	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// Executar o handler
	handler.TokenEndpoint(rr, req)

	// Verificar o resultado
	assert.Equal(t, http.StatusOK, rr.Code, "Deve responder com status 200 OK")
	assert.Equal(t, "application/json;charset=UTF-8", rr.Header().Get("Content-Type"), "Tipo de conteúdo deve ser JSON")

	// Verificar o corpo da resposta
	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	assert.Equal(t, "test_access_token", response["access_token"])
	assert.Equal(t, "bearer", response["token_type"])
	assert.Equal(t, float64(3600), response["expires_in"])
	assert.Equal(t, "test_refresh_token", response["refresh_token"])
	assert.Equal(t, "openid profile", response["scope"])

	// Verificar se todos os métodos do mock foram chamados corretamente
	provider.AssertExpectations(t)
	accessRequest.AssertExpectations(t)
	accessResponse.AssertExpectations(t)
}

// TestIntrospectionEndpoint testa o endpoint de introspecção de token
func TestIntrospectionEndpoint(t *testing.T) {
	// Configurar o mock do OAuth2Provider
	provider := new(MockOAuth2Provider)

	// Criar um mock de IntrospectionResponder
	introspectionResponse := new(MockIntrospectionResponse)

	// Configurar resposta de introspecção
	introspectionData := map[string]interface{}{
		"active":    true,
		"scope":     "openid profile",
		"client_id": "client123",
		"username":  "testuser",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}

	// Configurar expectativas para o mock
	provider.On("NewIntrospectionRequest", mock.Anything, mock.Anything, mock.Anything).Return(introspectionResponse, nil)
	provider.On("WriteIntrospectionResponse", mock.Anything, mock.Anything, introspectionResponse).Run(func(args mock.Arguments) {
		resp := args.Get(1).(http.ResponseWriter)
		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		json.NewEncoder(resp).Encode(introspectionData)
	})
	// Adicionar expectativa para IntrospectToken
	provider.On("IntrospectToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(fosite.TokenType(""), nil, nil)

	introspectionResponse.On("ToMap").Return(introspectionData)

	// Criar o handler OAuth2 com o mock de provider
	handler := &OAuth2Handler{
		Provider:  provider,
		Sessions:  make(map[string]*Session),
		Templates: nil,
	}

	// Criar uma requisição HTTP de teste
	formData := url.Values{}
	formData.Add("token", "test_token")
	formData.Add("token_type_hint", "access_token")

	req := httptest.NewRequest("POST", "/oauth2/introspect", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client123", "secret456")
	rr := httptest.NewRecorder()

	// Executar o handler
	handler.IntrospectionEndpoint(rr, req)

	// Verificar o resultado
	assert.Equal(t, http.StatusOK, rr.Code, "Deve responder com status 200 OK")

	// Verificar o corpo da resposta
	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	assert.Equal(t, true, response["active"])
	assert.Equal(t, "openid profile", response["scope"])
	assert.Equal(t, "client123", response["client_id"])

	// Verificar se todos os métodos do mock foram chamados corretamente
	provider.AssertExpectations(t)
	introspectionResponse.AssertExpectations(t)
}

// TestRevocationEndpoint testa o endpoint de revogação de token
func TestRevocationEndpoint(t *testing.T) {
	// Configurar o mock do OAuth2Provider
	provider := new(MockOAuth2Provider)

	// Configurar expectativas para o mock
	provider.On("NewRevocationRequest", mock.Anything, mock.Anything).Return(nil)
	provider.On("WriteRevocationResponse", mock.Anything, mock.Anything, nil).Run(func(args mock.Arguments) {
		resp := args.Get(1).(http.ResponseWriter)
		resp.WriteHeader(http.StatusOK)
	})
	// Adicionar expectativa para IntrospectToken
	provider.On("IntrospectToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(fosite.TokenType(""), nil, nil)

	// Criar o handler OAuth2 com o mock de provider
	handler := &OAuth2Handler{
		Provider:  provider,
		Sessions:  make(map[string]*Session),
		Templates: nil,
	}

	// Criar uma requisição HTTP de teste
	formData := url.Values{}
	formData.Add("token", "test_token")
	formData.Add("token_type_hint", "access_token")

	req := httptest.NewRequest("POST", "/oauth2/revoke", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client123", "secret456")
	rr := httptest.NewRecorder()

	// Executar o handler
	handler.RevocationEndpoint(rr, req)

	// Verificar o resultado
	assert.Equal(t, http.StatusOK, rr.Code, "Deve responder com status 200 OK")

	// Verificar se todos os métodos do mock foram chamados corretamente
	provider.AssertExpectations(t)
}

// TestLoginHandler_GET testa a exibição da página de login
func TestLoginHandler_GET(t *testing.T) {
	// Criar uma sessão fictícia para teste
	sessions := map[string]*Session{
		"test_session_id": {
			OriginalAuthURL: "/oauth2/auth?client_id=client123&response_type=code",
			CSRFToken:       "test_csrf_token",
		},
	}

	// Criar template básico para teste
	tmpl := `
		<!DOCTYPE html>
		<html>
		<head><title>Login</title></head>
		<body>
			<h1>Login</h1>
			<form method="post">
				{{ .CSRFTokenField }}
				<input type="text" name="username">
				<input type="password" name="password">
				<button type="submit">Login</button>
			</form>
		</body>
		</html>
	`
	templates, err := loadTestTemplate("login.html", tmpl)
	assert.NoError(t, err, "Deve carregar template de teste sem erros")

	// Criar o handler OAuth2 com as sessões de teste
	handler := &OAuth2Handler{
		Provider:  nil, // Não precisamos do provider para este teste
		Sessions:  sessions,
		Templates: templates,
	}

	// Criar uma requisição HTTP GET de teste
	req := httptest.NewRequest("GET", "/login?session_id=test_session_id", nil)
	rr := httptest.NewRecorder()

	// Executar o handler
	handler.LoginHandler(rr, req)

	// Verificar o resultado
	assert.Equal(t, http.StatusOK, rr.Code, "Deve responder com status 200 OK")
	assert.Contains(t, rr.Body.String(), "Login", "Deve conter o título da página de login")
	assert.Contains(t, rr.Body.String(), "test_csrf_token", "Deve conter o token CSRF")
}

// TestLoginHandler_POST_Success testa o login bem-sucedido
func TestLoginHandler_POST_Success(t *testing.T) {
	// Criar uma sessão fictícia para teste
	sessions := map[string]*Session{
		"test_session_id": {
			OriginalAuthURL: "/oauth2/auth?client_id=client123&response_type=code",
			CSRFToken:       "test_csrf_token",
		},
	}

	// Criar o handler OAuth2 com as sessões de teste
	handler := &OAuth2Handler{
		Provider:  nil, // Não precisamos do provider para este teste
		Sessions:  sessions,
		Templates: nil, // Não precisamos de templates para este teste POST
	}

	// Criar uma requisição HTTP POST de teste com credenciais válidas
	formData := url.Values{}
	formData.Add("username", "user")
	formData.Add("password", "password")
	formData.Add("csrf_token", "test_csrf_token")

	req := httptest.NewRequest("POST", "/login?session_id=test_session_id", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// Executar o handler
	handler.LoginHandler(rr, req)

	// Verificar o resultado
	assert.Equal(t, http.StatusFound, rr.Code, "Deve redirecionar após login bem-sucedido")

	location := rr.Header().Get("Location")
	assert.Equal(t, "/oauth2/auth?client_id=client123&response_type=code", location, "Deve redirecionar para a URL original de autorização")

	// Verificar se a sessão original foi excluída
	_, exists := handler.Sessions["test_session_id"]
	assert.False(t, exists, "A sessão temporária de login deve ser excluída")

	// Verificar se uma nova sessão autenticada foi criada
	assert.Equal(t, 1, len(handler.Sessions), "Deve existir uma sessão autenticada")

	// Obter o ID da nova sessão do cookie
	cookies := rr.Result().Cookies()
	var sessionID string
	for _, c := range cookies {
		if c.Name == "auth_session_id" {
			sessionID = c.Value
			break
		}
	}

	// Verificar a nova sessão
	newSession, exists := handler.Sessions[sessionID]
	assert.True(t, exists, "A nova sessão autenticada deve existir")
	assert.Equal(t, "user", newSession.UserID, "A sessão deve conter o nome do usuário")
	assert.True(t, newSession.AuthenticatedAt.Before(time.Now()), "O tempo de autenticação deve estar no passado")
}

// TestLoginHandler_POST_InvalidCredentials testa o login com credenciais inválidas
func TestLoginHandler_POST_InvalidCredentials(t *testing.T) {
	// Criar uma sessão fictícia para teste
	sessions := map[string]*Session{
		"test_session_id": {
			OriginalAuthURL: "/oauth2/auth?client_id=client123&response_type=code",
			CSRFToken:       "test_csrf_token",
		},
	}

	// Criar template básico para teste
	tmpl := `
		<!DOCTYPE html>
		<html>
		<head><title>Login</title></head>
		<body>
			<h1>Login</h1>
			<form method="post">
				{{ .CSRFTokenField }}
				<input type="text" name="username">
				<input type="password" name="password">
				<button type="submit">Login</button>
				{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
			</form>
		</body>
		</html>
	`
	templates, err := template.New("login.html").Parse(tmpl)
	assert.NoError(t, err, "Deve carregar template de teste sem erros")

	// Criar o handler OAuth2 com as sessões de teste
	handler := &OAuth2Handler{
		Provider:  nil,
		Sessions:  sessions,
		Templates: templates,
	}

	// Criar uma requisição HTTP POST de teste com credenciais inválidas
	formData := url.Values{}
	formData.Add("username", "invalid")
	formData.Add("password", "invalid")
	formData.Add("csrf_token", "test_csrf_token")

	req := httptest.NewRequest("POST", "/login?session_id=test_session_id", strings.NewReader(formData.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// Executar o handler
	handler.LoginHandler(rr, req)

	// Verificar o resultado
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Deve responder com status 401 Unauthorized")
	assert.Contains(t, rr.Body.String(), "Nome de usuário ou senha inválidos", "Deve conter uma mensagem de erro")

	// Verificar que a sessão ainda existe
	_, exists := handler.Sessions["test_session_id"]
	assert.True(t, exists, "A sessão temporária de login deve ainda existir após falha")
}

// Função auxiliar para criar templates de teste
func loadTestTemplate(name, content string) (*template.Template, error) {
	return template.New(name).Parse(content)
}
