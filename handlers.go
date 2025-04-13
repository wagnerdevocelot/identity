package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	// "github.com/gorilla/csrf" // Removed temporarily - unused
)

var templates *template.Template

func init() {
	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}
}

// --- Simple Session Management (Replace with proper session handling) ---

// Session stores information about the user's session and the ongoing auth request.
// WARNING: This is a simplistic in-memory session for demonstration.
// Use a secure, persistent session mechanism in production (e.g., gorilla/sessions, database-backed).
type Session struct {
	UserID          string
	AuthenticatedAt time.Time
	ConsentGranted  bool   // Flag to check if consent was given for this request
	OriginalAuthURL string // Store the original /oauth2/auth request URL
	RequestedScopes []string
	GrantedScopes   []string
	ClientID        string
	Form            url.Values // Store form values from consent page
	CSRFToken       string     // Added for CSRF protection
}

// Dummy session store (replace with real implementation)
var sessions = make(map[string]*Session) // Map session ID (e.g., cookie value) to Session

// generateCSRFToken creates a random CSRF token.
// Renamed to GenerateCSRFToken for export
func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// getUserSession retrieves the user session based on a request (e.g., cookie).
// Returns nil if no valid session found.
func getUserSession(r *http.Request) *Session {
	// In a real app, get session ID from a secure cookie
	// and look it up in your session store (Redis, DB, etc.)
	cookie, err := r.Cookie("auth_session_id")
	if err != nil {
		return nil // No session cookie
	}
	sess, exists := sessions[cookie.Value]
	if !exists {
		return nil // Session expired or invalid
	}
	// Basic check: Assume session is valid if it exists
	// In a real app, add expiry checks, etc.
	if sess.UserID == "" && r.URL.Path != "/login" && r.URL.Path != "/consent" {
		// Allow access to login/consent even without UserID if session exists
		// But for other paths, require UserID
		// This logic might need refinement based on exact flow.
	} else if sess.UserID == "" && r.URL.Path != "/login" && r.URL.Path != "/consent" {
		return nil // Not authenticated for paths other than login/consent
	}
	return sess
}

// createOrUpdateSession creates or updates a session.
// In a real app, this would set a secure cookie.
func createOrUpdateSession(w http.ResponseWriter, sessionID string, sess *Session) {
	sessions[sessionID] = sess
	cookie := &http.Cookie{
		Name:     "auth_session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Hardcoded: TODO: Determine Secure flag based on request or config
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour), // Example expiry
	}
	http.SetCookie(w, cookie)
}

// --- OAuth2 Handlers ---

// authEndpoint handles the OAuth 2.0 authorization requests (/oauth2/auth)
func authEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse the authorization request
	ar, err := oauth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
		oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// --- User Authentication Check ---
	session := getUserSession(r)
	if session == nil || session.UserID == "" {
		// User not authenticated, redirect to login page.
		// Store the original request details to redirect back after login.
		loginSessionID := "login_session_" + fmt.Sprint(time.Now().UnixNano()) // Simple unique ID
		// Use exported function name
		csrf, err := GenerateCSRFToken()
		if err != nil {
			http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
			return
		}
		loginSess := &Session{
			OriginalAuthURL: r.URL.String(), // Store the full auth URL
			CSRFToken:       csrf,
		}
		createOrUpdateSession(w, loginSessionID, loginSess)

		// Redirect to login, passing the temporary session ID
		http.Redirect(w, r, "/login?session_id="+loginSessionID, http.StatusFound)
		return
	}

	// --- Consent Check ---
	// In a real app, you would check if the user has previously consented
	// to these scopes for this client. If prompt=consent is requested, always show consent.
	needsConsent := true // Assume consent is needed for simplicity

	// Example: Check if *only* openid is requested and maybe auto-grant
	if len(ar.GetRequestedScopes()) == 1 && ar.GetRequestedScopes().Has("openid") {
		// needsConsent = false // Uncomment to auto-grant if only 'openid'
		// ar.GrantScope("openid")
	}

	prompt := ar.GetRequestForm().Get("prompt")
	if prompt == "consent" {
		needsConsent = true
	}

	// Get client info for the consent page
	client, err := store.GetClient(ctx, ar.GetClient().GetID())
	if err != nil {
		log.Printf("Error finding client: %+v", err)
		wrappedErr := fmt.Errorf("failed to get client %s: %w", ar.GetClient().GetID(), err)
		oauth2Provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithHint(wrappedErr.Error()))
		return
	}

	if needsConsent && !session.ConsentGranted {
		// Generate CSRF token for consent form
		// Use exported function name
		csrf, err := GenerateCSRFToken()
		if err != nil {
			http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
			return
		}

		// Redirect to consent page
		// Store necessary details in the session for the consent handler
		session.OriginalAuthURL = r.URL.String() // Keep the original auth URL
		session.RequestedScopes = ar.GetRequestedScopes()
		session.ClientID = client.GetID()
		session.ConsentGranted = false // Mark consent as not yet granted for this flow
		session.CSRFToken = csrf       // Store CSRF token

		// Use the existing session ID from the cookie
		cookie, err := r.Cookie("auth_session_id")
		if err != nil { // Should have cookie if user is authenticated
			http.Error(w, "Missing session cookie", http.StatusInternalServerError)
			return
		}
		createOrUpdateSession(w, cookie.Value, session)

		consentURL := "/consent?session_id=" + cookie.Value
		http.Redirect(w, r, consentURL, http.StatusFound)
		return
	}

	// --- Grant Access ---
	// User is authenticated and has given consent (or it wasn't needed).

	// Set the user ID in the session context for Fosite
	// This is typically done after successful authentication & consent.
	mySessionData := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: session.UserID, // The authenticated user's ID
			// Add other claims like email, profile, etc., based on granted scopes
			// Ensure these match the scopes the user actually granted!
			Extra: make(map[string]interface{}),
		},
		Headers: &jwt.Headers{},
		Subject: session.UserID,
	}

	// Grant the scopes. If consent flow was skipped, grant all requested scopes.
	// If consent flow happened, grant scopes from session.GrantedScopes.
	if !needsConsent {
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
	} else {
		for _, scope := range session.GrantedScopes {
			ar.GrantScope(scope)
		}
	}

	// Generate the authorization response (code, token, id_token)
	response, err := oauth2Provider.NewAuthorizeResponse(ctx, ar, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %+v", err)
		oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Send the response back to the client
	oauth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)

	// Clean up consent flag and CSRF token for the next request
	session.ConsentGranted = false
	session.GrantedScopes = nil
	session.RequestedScopes = nil
	session.ClientID = ""
	session.OriginalAuthURL = ""
	session.CSRFToken = ""                   // Clear CSRF token after use
	cookie, _ := r.Cookie("auth_session_id") // Reuse existing cookie value
	createOrUpdateSession(w, cookie.Value, session)
}

// tokenEndpoint handles the OAuth 2.0 token requests (/oauth2/token)
func tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Create a new session object for Fosite.
	// For grant types like client_credentials or refresh_token, user session might not be relevant.
	// For authorization_code grant, Fosite retrieves the session associated with the code.
	mySessionData := &openid.DefaultSession{
		Claims:  &jwt.IDTokenClaims{Extra: make(map[string]interface{})},
		Headers: &jwt.Headers{},
	}

	// Parse the access request
	ar, err := oauth2Provider.NewAccessRequest(ctx, r, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %+v", err)
		oauth2Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// If this is a refresh_token grant, you might want to check if the user is still valid
	if ar.GetGrantTypes().Exact("refresh_token") {
		// Look up the user from the session associated with the refresh token
		// userID := mySessionData.GetSubject() ... check if user is active ...
	}

	// Generate the access response
	response, err := oauth2Provider.NewAccessResponse(ctx, ar)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %+v", err)
		oauth2Provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	// Send the response back to the client
	oauth2Provider.WriteAccessResponse(ctx, w, ar, response)
}

// loginHandler handles user login form display and submission
func loginHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id", http.StatusBadRequest)
		return
	}

	loginSess, exists := sessions[sessionID]
	if !exists || loginSess.OriginalAuthURL == "" {
		http.Error(w, "Invalid or expired login session", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		// Display login form using template
		w.Header().Set("Content-Type", "text/html")
		data := map[string]interface{}{
			"SessionID":      sessionID,
			"CSRFTokenField": template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, loginSess.CSRFToken)),
			"Error":          nil, // Add error message if needed from previous attempt
		}
		err := templates.ExecuteTemplate(w, "login.html", data)
		if err != nil {
			log.Printf("Error executing login template: %v", err)
			http.Error(w, "Failed to render login page", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		// --- CSRF Check ---
		submittedCSRF := r.FormValue("csrf_token")
		if submittedCSRF == "" || submittedCSRF != loginSess.CSRFToken {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		// --- Dummy Authentication ---
		// Replace with your actual user authentication logic (check password hash, etc.)
		if username == "user" && password == "password" {
			// Authentication successful
			log.Printf("User '%s' authenticated successfully", username)

			// Create a persistent session for the authenticated user
			userSessionID := "user_session_" + username + "_" + fmt.Sprint(time.Now().UnixNano())
			userSess := &Session{
				UserID:          username,
				AuthenticatedAt: time.Now(),
			}
			createOrUpdateSession(w, userSessionID, userSess)

			// Redirect back to the original /oauth2/auth URL stored in the login session
			originalAuthURL := loginSess.OriginalAuthURL
			delete(sessions, sessionID) // Clean up temporary login session

			http.Redirect(w, r, originalAuthURL, http.StatusFound)
			return
		} else {
			// Authentication failed
			log.Printf("Authentication failed for user '%s'", username)

			// Redisplay login form with an error message
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized) // Set appropriate status code
			data := map[string]interface{}{
				"SessionID":      sessionID,
				"CSRFTokenField": template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, loginSess.CSRFToken)),
				"Error":          "Invalid username or password",
			}
			err := templates.ExecuteTemplate(w, "login.html", data)
			if err != nil {
				log.Printf("Error executing login template after failure: %v", err)
				http.Error(w, "Failed to render login page", http.StatusInternalServerError)
			}
			return
		}
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// consentHandler handles user consent form display and submission
func consentHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id", http.StatusBadRequest)
		return
	}

	sess, exists := sessions[sessionID]
	if !exists || sess.OriginalAuthURL == "" || sess.ClientID == "" {
		http.Error(w, "Invalid or expired consent session", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	// Re-parse the original authorize request using the stored URL
	// Note: It might be better to store the AuthorizeRequest object itself in the session if possible,
	// or at least all necessary parameters, to avoid potential issues with re-parsing.
	originalReq, err := http.NewRequestWithContext(ctx, "GET", sess.OriginalAuthURL, nil)
	if err != nil {
		http.Error(w, "Failed to reconstruct original request", http.StatusInternalServerError)
		return
	}
	ar, err := oauth2Provider.NewAuthorizeRequest(ctx, originalReq)
	if err != nil {
		log.Printf("Error re-parsing authorize request in consent: %+v", err)
		oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	if r.Method == http.MethodGet {
		// Display consent form using template
		client, _ := store.GetClient(ctx, sess.ClientID)
		w.Header().Set("Content-Type", "text/html")
		data := map[string]interface{}{
			"ClientID":        client.GetID(), // Use client.GetName() if available
			"RequestedScopes": sess.RequestedScopes,
			"SessionID":       sessionID,
			"CSRFTokenField":  template.HTML(fmt.Sprintf(`<input type="hidden" name="csrf_token" value="%s">`, sess.CSRFToken)),
		}
		err := templates.ExecuteTemplate(w, "consent.html", data)
		if err != nil {
			log.Printf("Error executing consent template: %v", err)
			http.Error(w, "Failed to render consent page", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		// --- CSRF Check ---
		submittedCSRF := r.FormValue("csrf_token")
		if submittedCSRF == "" || submittedCSRF != sess.CSRFToken {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		consentAction := r.FormValue("consent")

		if consentAction == "Deny" {
			// User denied access
			err := fosite.ErrAccessDenied.WithDescription("The resource owner denied the request")
			oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
			delete(sessions, sessionID) // Clean up session
			return
		}

		if consentAction == "Allow" {
			grantedScopes := r.Form["scopes"]

			// Mark consent granted in session and store granted scopes
			sess.ConsentGranted = true
			sess.GrantedScopes = grantedScopes
			sess.Form = r.Form // Store form data if needed by Fosite later
			createOrUpdateSession(w, sessionID, sess)

			// Redirect back to the original /oauth2/auth handler,
			// which will now find ConsentGranted = true and proceed.
			http.Redirect(w, r, sess.OriginalAuthURL, http.StatusFound)
			return
		}

		// Invalid action
		http.Error(w, "Invalid consent action", http.StatusBadRequest)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Helper to write JSON errors
func writeJsonError(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) // Ignore error on write
}
