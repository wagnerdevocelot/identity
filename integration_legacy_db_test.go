package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// setupLegacyStore initializes the global store with a LoggingAdapter over LegacyDBAdapter.
func setupLegacyStore(t *testing.T) func() {
	db := setupTestDB(t)
	orig := store
	adapter := NewLegacyDBAdapter(db)
	// seed client similar to in-memory store
	client := &fosite.DefaultClient{
		ID:            "my-test-client",
		Secret:        []byte("foobar"),
		RedirectURIs:  []string{"http://localhost:3000/callback", "http://127.0.0.1:3000/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token", "client_credentials"},
		ResponseTypes: fosite.Arguments{"code", "token", "id_token", "code id_token", "code token", "id_token token", "code id_token token"},
		Scopes:        fosite.Arguments{"openid", "profile", "email", "offline"},
		Audience:      fosite.Arguments{"https://my-api.com"},
	}
	if err := adapter.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	store = adapter
	return func() { store = orig }
}

// TestFullFlowLegacyDB simulates login, consent, token issuance and validation using the legacy DB.
func TestFullFlowLegacyDB(t *testing.T) {
	teardown := setupLegacyStore(t)
	defer teardown()

	// mimic authorization code flow using fosite directly
	router := setupRouter()
	srv := httptest.NewServer(router)
	defer srv.Close()

	// create authorize request manually
	arReq, _ := http.NewRequest("GET", srv.URL+"/oauth2/auth?response_type=code&client_id=my-test-client&redirect_uri=http://localhost:3000/callback&scope=openid+profile+offline&state=12345678", nil)
	ar, err := oauth2Provider.NewAuthorizeRequest(arReq.Context(), arReq)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	ar.GrantScope("openid")
	ar.GrantScope("profile")
	ar.GrantScope("offline")
	sess := &openid.DefaultSession{Claims: &jwt.IDTokenClaims{Subject: "user"}, Headers: &jwt.Headers{}, Subject: "user"}
	resp, err := oauth2Provider.NewAuthorizeResponse(arReq.Context(), ar, sess)
	if err != nil {
		t.Fatalf("authorize response: %v", err)
	}
	recorder := httptest.NewRecorder()
	oauth2Provider.WriteAuthorizeResponse(arReq.Context(), recorder, ar, resp)
	location, _ := recorder.Result().Location()
	code := location.Query().Get("code")

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:3000/callback")
	tokenReq, _ := http.NewRequest("POST", srv.URL+"/oauth2/token", strings.NewReader(data.Encode()))
	tokenReq.SetBasicAuth("my-test-client", "foobar")
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resToken, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("token request err: %v", err)
	}
	var tokenResp map[string]interface{}
	json.NewDecoder(resToken.Body).Decode(&tokenResp)
	resToken.Body.Close()

	access := tokenResp["access_token"].(string)

	introspect := url.Values{"token": {access}}
	introReq, _ := http.NewRequest("POST", srv.URL+"/oauth2/introspect", strings.NewReader(introspect.Encode()))
	introReq.SetBasicAuth("my-test-client", "foobar")
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resIntro, err := http.DefaultClient.Do(introReq)
	if err != nil {
		t.Fatalf("introspect err: %v", err)
	}
	var introResp map[string]interface{}
	json.NewDecoder(resIntro.Body).Decode(&introResp)
	resIntro.Body.Close()
	if active, ok := introResp["active"].(bool); !ok || !active {
		t.Errorf("token not active: %v", introResp)
	}
}
