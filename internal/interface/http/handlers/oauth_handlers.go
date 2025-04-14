// Package handlers contém os controladores HTTP para a aplicação.
package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Estrutura para armazenar os handlers e suas dependências
type OAuth2Handler struct {
	Provider  fosite.OAuth2Provider
	Store     interface{} // Será tipada conforme a interface específica
	Templates *template.Template
	Sessions  map[string]*Session // Temporário, substituir por implementação de sessão mais robusta
}

// Session armazena informações sobre a sessão do usuário e a requisição de autenticação em andamento.
// AVISO: Esta é uma sessão em memória simplista para demonstração.
// Use um mecanismo de sessão seguro e persistente em produção (como gorilla/sessions, com banco de dados).
type Session struct {
	UserID          string
	AuthenticatedAt time.Time
	ConsentGranted  bool   // Flag para verificar se o consentimento foi dado para esta requisição
	OriginalAuthURL string // Armazena a URL original da requisição /oauth2/auth
	RequestedScopes []string
	GrantedScopes   []string
	ClientID        string
	Form            url.Values // Armazena valores de formulário da página de consentimento
	CSRFToken       string     // Adicionado para proteção CSRF
}

// NewOAuth2Handler cria um novo handler OAuth2 com suas dependências
func NewOAuth2Handler(provider fosite.OAuth2Provider, store interface{}) *OAuth2Handler {
	// Verificar se existe uma variável de ambiente para o caminho dos templates
	templatesPath := os.Getenv("TEMPLATES_PATH")
	if templatesPath == "" {
		// Se não houver variável de ambiente, usar o caminho relativo padrão
		templatesPath = "templates"
	}

	// Montar o padrão de busca para os templates
	templatesPattern := filepath.Join(templatesPath, "*.html")

	templates, err := template.ParseGlob(templatesPattern)
	if err != nil {
		log.Fatalf("Falha ao analisar templates: %v", err)
	}

	return &OAuth2Handler{
		Provider:  provider,
		Store:     store,
		Templates: templates,
		Sessions:  make(map[string]*Session),
	}
}

// GenerateCSRFToken cria um token CSRF aleatório.
func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// SetupRouter configura todas as rotas HTTP da aplicação
func SetupRouter(provider fosite.OAuth2Provider, store interface{}) http.Handler {
	handler := NewOAuth2Handler(provider, store)

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/auth", handler.AuthEndpoint)
	mux.HandleFunc("/oauth2/token", handler.TokenEndpoint)
	mux.HandleFunc("/oauth2/introspect", handler.IntrospectionEndpoint)
	mux.HandleFunc("/oauth2/revoke", handler.RevocationEndpoint)
	mux.HandleFunc("/login", handler.LoginHandler)
	mux.HandleFunc("/consent", handler.ConsentHandler)

	return mux
}

// AuthEndpoint lida com as requisições de autorização OAuth 2.0 (/oauth2/auth)
func (h *OAuth2Handler) AuthEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Analisar a requisição de autorização
	ar, err := h.Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.Printf("Erro ocorrido em NewAuthorizeRequest: %+v", err)
		h.Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// --- Verificação de Autenticação do Usuário ---
	session := h.getUserSession(r)
	if session == nil || session.UserID == "" {
		// Usuário não autenticado, redireciona para página de login.
		// Armazena os detalhes da requisição original para redirecionamento após o login.
		loginSessionID := "login_session_" + fmt.Sprint(time.Now().UnixNano()) // ID único simples
		csrf, err := GenerateCSRFToken()
		if err != nil {
			http.Error(w, "Falha ao gerar token CSRF", http.StatusInternalServerError)
			return
		}
		loginSess := &Session{
			OriginalAuthURL: r.URL.String(), // Armazena a URL auth completa
			CSRFToken:       csrf,
		}
		h.createOrUpdateSession(w, r, loginSessionID, loginSess) // Passar 'r'

		// Redireciona para login, passando o ID de sessão temporário
		http.Redirect(w, r, "/login?session_id="+loginSessionID, http.StatusFound)
		return
	}

	// --- Verificação de Consentimento ---
	// Em um app real, você verificaria se o usuário já consentiu anteriormente
	// a estes escopos para este cliente. Se prompt=consent for solicitado, sempre mostre consentimento.
	needsConsent := true // Assume que o consentimento é necessário para simplicidade

	// Exemplo: Verificar se *apenas* openid foi solicitado e talvez auto-conceder
	if len(ar.GetRequestedScopes()) == 1 && ar.GetRequestedScopes().Has("openid") {
		// needsConsent = false // Descomente para auto-conceder se apenas 'openid'
		// ar.GrantScope("openid")
	}

	prompt := ar.GetRequestForm().Get("prompt")
	if prompt == "consent" {
		needsConsent = true
	}

	// Obter informações do cliente para a página de consentimento
	// O cliente é obtido através do armazenamento (Store) que deve implementar fosite.ClientManager
	clientStore, ok := h.Store.(fosite.ClientManager)
	if !ok {
		log.Printf("Erro interno: O armazenamento configurado não implementa fosite.ClientManager")
		h.Provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithHint("Erro interno do servidor."))
		return
	}
	clientID := ar.GetClient().GetID()
	client, err := clientStore.GetClient(ctx, clientID)
	if err != nil {
		log.Printf("Erro ao encontrar cliente '%s': %+v", clientID, err)
		wrappedErr := fmt.Errorf("falha ao obter cliente %s: %w", clientID, err)
		// Use fosite.ErrNotFound for client not found, otherwise ErrServerError
		if e, ok := err.(*fosite.RFC6749Error); ok && e.StatusCode() == http.StatusNotFound {
			h.Provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrInvalidClient.WithHintf("Cliente '%s' não encontrado.", clientID).WithWrap(err))
		} else {
			h.Provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithHint(wrappedErr.Error()).WithWrap(err))
		}
		return
	}

	if needsConsent && !session.ConsentGranted {
		// Gerar token CSRF para formulário de consentimento
		csrf, err := GenerateCSRFToken()
		if err != nil {
			http.Error(w, "Falha ao gerar token CSRF", http.StatusInternalServerError)
			return
		}

		// Redirecionar para página de consentimento
		// Armazenar detalhes necessários na sessão para o handler de consentimento
		session.OriginalAuthURL = r.URL.String() // Manter a URL auth original
		session.RequestedScopes = ar.GetRequestedScopes()
		session.ClientID = client.GetID()
		session.ConsentGranted = false // Marcar consentimento como ainda não concedido para este fluxo
		session.CSRFToken = csrf       // Armazenar token CSRF

		// Usar o ID de sessão existente do cookie
		cookie, err := r.Cookie("auth_session_id")
		if err != nil { // Deve ter cookie se usuário estiver autenticado
			http.Error(w, "Cookie de sessão ausente", http.StatusInternalServerError)
			return
		}
		h.createOrUpdateSession(w, r, cookie.Value, session) // Passar 'r'

		consentURL := "/consent?session_id=" + cookie.Value
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	// --- Conceder Acesso ---
	// Usuário está autenticado e deu consentimento (ou não era necessário).

	// Definir o ID do usuário no contexto da sessão para o Fosite
	// Isso é tipicamente feito após autenticação e consentimento bem-sucedidos.
	mySessionData := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: session.UserID, // O ID do usuário autenticado
			// Adicionar outras claims como email, perfil, etc., com base nos escopos concedidos
			// Certifique-se de que correspondam aos escopos que o usuário realmente concedeu!
			Extra: make(map[string]interface{}),
		},
		Headers: &jwt.Headers{},
		Subject: session.UserID,
	}

	// Conceder os escopos. Se o fluxo de consentimento foi pulado, conceder todos os escopos solicitados.
	// Se o fluxo de consentimento aconteceu, conceder escopos de session.GrantedScopes.
	if !needsConsent {
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
	} else {
		for _, scope := range session.GrantedScopes {
			ar.GrantScope(scope)
		}
	}

	// Gerar a resposta de autorização (código, token, id_token)
	response, err := h.Provider.NewAuthorizeResponse(ctx, ar, mySessionData)
	if err != nil {
		log.Printf("Erro ocorrido em NewAuthorizeResponse: %+v", err)
		h.Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Enviar a resposta de volta ao cliente
	h.Provider.WriteAuthorizeResponse(ctx, w, ar, response)

	// Limpar flag de consentimento e token CSRF para a próxima requisição
	session.ConsentGranted = false
	session.GrantedScopes = nil
	session.RequestedScopes = nil
	session.ClientID = ""
	session.OriginalAuthURL = ""
	session.CSRFToken = ""                               // Limpar token CSRF após uso
	cookie, _ := r.Cookie("auth_session_id")             // Reusar valor de cookie existente
	h.createOrUpdateSession(w, r, cookie.Value, session) // Passar 'r'
}

// TokenEndpoint lida com as requisições de token OAuth 2.0 (/oauth2/token)
func (h *OAuth2Handler) TokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Criar um novo objeto de sessão para o Fosite.
	// Para tipos de concessão como client_credentials ou refresh_token, a sessão do usuário pode não ser relevante.
	// Para autorização_código, o Fosite recupera a sessão associada ao código.
	mySessionData := &openid.DefaultSession{
		Claims:  &jwt.IDTokenClaims{Extra: make(map[string]interface{})},
		Headers: &jwt.Headers{},
	}

	// Analisar a requisição de acesso
	ar, err := h.Provider.NewAccessRequest(ctx, r, mySessionData)
	if err != nil {
		log.Printf("Erro ocorrido em NewAccessRequest: %+v", err)
		h.Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Se esta é uma concessão refresh_token, você pode querer verificar se o usuário ainda é válido
	if ar.GetGrantTypes().Exact("refresh_token") {
		// Procurar o usuário na sessão associada ao token de atualização
		// userID := mySessionData.GetSubject() ... verificar se o usuário está ativo ...
	}

	// Gerar a resposta de acesso
	response, err := h.Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		log.Printf("Erro ocorrido em NewAccessResponse: %+v", err)
		h.Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Enviar a resposta de volta ao cliente
	h.Provider.WriteAccessResponse(ctx, w, ar, response)
}

// IntrospectionEndpoint lida com as requisições de introspecção de token
func (h *OAuth2Handler) IntrospectionEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()                    // Usar contexto da requisição diretamente
	session := new(openid.DefaultSession) // Usar tipo de sessão apropriado
	ir, err := h.Provider.NewIntrospectionRequest(ctx, r, session)
	if err != nil {
		log.Printf("Requisição de introspecção falhou: %+v", err)
		h.Provider.WriteIntrospectionError(ctx, w, err) // Adicionar ctx
		return
	}
	h.Provider.WriteIntrospectionResponse(ctx, w, ir) // Adicionar ctx
}

// RevocationEndpoint lida com as requisições de revogação de token
func (h *OAuth2Handler) RevocationEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context() // Usar contexto da requisição diretamente
	err := h.Provider.NewRevocationRequest(ctx, r)
	if err != nil {
		log.Printf("Requisição de revogação falhou: %+v", err)
	}
	h.Provider.WriteRevocationResponse(ctx, w, err) // Adicionar ctx
}

// LoginHandler lida com a exibição e submissão do formulário de login do usuário
func (h *OAuth2Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "session_id ausente", http.StatusBadRequest)
		return
	}

	loginSess, exists := h.Sessions[sessionID]
	if !exists || loginSess.OriginalAuthURL == "" {
		http.Error(w, "Sessão de login inválida ou expirada", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		// Exibir formulário de login usando template
		w.Header().Set("Content-Type", "text/html")
		data := map[string]interface{}{
			"SessionID":      sessionID,
			"CSRFTokenField": template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, loginSess.CSRFToken)),
			"Error":          nil, // Adicionar mensagem de erro se necessário de tentativa anterior
		}
		err := h.Templates.ExecuteTemplate(w, "login.html", data)
		if err != nil {
			log.Printf("Erro ao executar template de login: %v", err)
			http.Error(w, "Falha ao renderizar página de login", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Falha ao analisar formulário", http.StatusBadRequest)
			return
		}

		// --- Verificação CSRF ---
		submittedCSRF := r.FormValue("csrf_token")
		if submittedCSRF == "" || submittedCSRF != loginSess.CSRFToken {
			http.Error(w, "Token CSRF inválido", http.StatusForbidden)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		// --- Autenticação Fictícia ---
		// Substitua por sua lógica real de autenticação de usuário (verificar hash de senha, etc.)
		if username == "user" && password == "password" {
			// Autenticação bem-sucedida
			log.Printf("Usuário '%s' autenticado com sucesso", username)

			// Criar uma sessão persistente para o usuário autenticado
			userSessionID := "user_session_" + username + "_" + fmt.Sprint(time.Now().UnixNano())
			userSess := &Session{
				UserID:          username,
				AuthenticatedAt: time.Now(),
			}
			h.createOrUpdateSession(w, r, userSessionID, userSess) // Passar 'r'

			// Redirecionar de volta para a URL /oauth2/auth original armazenada na sessão de login
			originalAuthURL := loginSess.OriginalAuthURL
			delete(h.Sessions, sessionID) // Limpar sessão de login temporária

			http.Redirect(w, r, originalAuthURL, http.StatusFound)
			return
		} else {
			// Autenticação falhou
			log.Printf("Autenticação falhou para usuário '%s'", username)

			// Exibir novamente formulário de login com mensagem de erro
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized) // Definir código de status apropriado
			data := map[string]interface{}{
				"SessionID":      sessionID,
				"CSRFTokenField": template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, loginSess.CSRFToken)),
				"Error":          "Nome de usuário ou senha inválidos",
			}
			err := h.Templates.ExecuteTemplate(w, "login.html", data)
			if err != nil {
				log.Printf("Erro ao executar template de login após falha: %v", err)
				http.Error(w, "Falha ao renderizar página de login", http.StatusInternalServerError)
			}
			return
		}
	}

	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

// ConsentHandler lida com a exibição e submissão do formulário de consentimento do usuário
func (h *OAuth2Handler) ConsentHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "session_id ausente", http.StatusBadRequest)
		return
	}

	sess, exists := h.Sessions[sessionID]
	if !exists || sess.OriginalAuthURL == "" || sess.ClientID == "" {
		http.Error(w, "Sessão de consentimento inválida ou expirada", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	// Reanalisar a requisição de autorização original usando a URL armazenada
	// Nota: Pode ser melhor armazenar o próprio objeto AuthorizeRequest na sessão se possível,
	// ou pelo menos todos os parâmetros necessários, para evitar problemas potenciais com reanálise.
	originalReq, err := http.NewRequestWithContext(ctx, "GET", sess.OriginalAuthURL, nil)
	if err != nil {
		http.Error(w, "Falha ao reconstruir requisição original", http.StatusInternalServerError)
		return
	}

	ar, err := h.Provider.NewAuthorizeRequest(ctx, originalReq)
	if err != nil {
		log.Printf("Erro ao reanalisar requisição de autorização no consentimento: %+v", err)
		h.Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	if r.Method == http.MethodGet {
		// Exibir formulário de consentimento usando template
		clientStore, ok := h.Store.(fosite.ClientManager)
		if !ok {
			log.Printf("Erro interno: O armazenamento configurado não implementa fosite.ClientManager")
			h.Provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithHint("Erro interno do servidor."))
			return
		}
		client, err := clientStore.GetClient(ctx, sess.ClientID)
		if err != nil {
			log.Printf("Erro ao obter cliente '%s' na página de consentimento: %+v", sess.ClientID, err)
			http.Error(w, "Erro ao obter informações do cliente", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		data := map[string]interface{}{
			"ClientID":        client.GetID(), // Usar client.GetName() se disponível
			"RequestedScopes": sess.RequestedScopes,
			"SessionID":       sessionID,
			"CSRFTokenField":  template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, sess.CSRFToken)),
		}
		err = h.Templates.ExecuteTemplate(w, "consent.html", data)
		if err != nil {
			log.Printf("Erro ao executar template de consentimento: %v", err)
			http.Error(w, "Falha ao renderizar página de consentimento", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Falha ao analisar formulário", http.StatusBadRequest)
			return
		}

		// --- Verificação CSRF ---
		submittedCSRF := r.FormValue("csrf_token")
		if submittedCSRF == "" || submittedCSRF != sess.CSRFToken {
			http.Error(w, "Token CSRF inválido", http.StatusForbidden)
			return
		}

		consentAction := r.FormValue("consent")

		if consentAction == "Deny" {
			// Usuário negou acesso
			err := fosite.ErrAccessDenied.WithDescription("O proprietário do recurso negou a requisição")
			h.Provider.WriteAuthorizeError(ctx, w, ar, err)
			delete(h.Sessions, sessionID) // Limpar sessão
			return
		}

		if consentAction == "Allow" {
			grantedScopes := r.Form["scopes"]

			// Marcar consentimento concedido na sessão e armazenar escopos concedidos
			sess.ConsentGranted = true
			sess.GrantedScopes = grantedScopes
			sess.Form = r.Form                             // Armazenar dados do formulário se necessário pelo Fosite depois
			h.createOrUpdateSession(w, r, sessionID, sess) // Passar 'r'

			// Redirecionar de volta para o handler /oauth2/auth original,
			// que agora encontrará ConsentGranted = true e prosseguirá.
			http.Redirect(w, r, sess.OriginalAuthURL, http.StatusFound)
			return
		}

		// Ação inválida
		http.Error(w, "Ação de consentimento inválida", http.StatusBadRequest)
		return
	}

	http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
}

// getUserSession recupera a sessão do usuário com base em uma requisição (por exemplo, cookie).
// Retorna nil se nenhuma sessão válida for encontrada.
func (h *OAuth2Handler) getUserSession(r *http.Request) *Session {
	// Em um app real, obter ID de sessão de um cookie seguro
	// e procurá-lo em seu armazenamento de sessão (Redis, DB, etc.)
	cookie, err := r.Cookie("auth_session_id")
	if err != nil {
		return nil // Sem cookie de sessão
	}
	sess, exists := h.Sessions[cookie.Value]
	if !exists {
		return nil // Sessão expirada ou inválida
	}
	// Verificação básica: Assume que a sessão é válida se existir
	// Em um app real, adicione verificações de expiração, etc.
	if sess.UserID == "" && r.URL.Path != "/login" && r.URL.Path != "/consent" {
		// Permitir acesso a login/consent mesmo sem UserID se a sessão existir
		// Mas para outros caminhos, exigir UserID
		// Esta lógica pode precisar de refinamento com base no fluxo exato.
	} else if sess.UserID == "" && r.URL.Path != "/login" && r.URL.Path != "/consent" {
		return nil // Não autenticado para caminhos que não sejam login/consent
	}
	return sess
}

// createOrUpdateSession cria ou atualiza uma sessão e define o cookie apropriado.
// Em um app real, isso interagiria com um armazenamento de sessão persistente.
func (h *OAuth2Handler) createOrUpdateSession(w http.ResponseWriter, r *http.Request, sessionID string, sess *Session) {
	h.Sessions[sessionID] = sess
	cookie := &http.Cookie{
		Name:     "auth_session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil, // Define Secure se a requisição for HTTPS
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour), // Expiração de exemplo
	}
	http.SetCookie(w, cookie)
}
