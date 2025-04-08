# Go OAuth2 Server Example (Fosite)

This project is an example OAuth 2.0 and OpenID Connect provider implemented in Go using the [ory/fosite](https://github.com/ory/fosite) library (v0.49.0+).

It provides basic OAuth 2.0 flows (Authorization Code, Client Credentials, Refresh Token) and includes simple HTML templates for user login and consent.

## Prerequisites

*   **Go:** Version 1.18 or higher. Ensure the Go executable is in your system's PATH or use the full path (e.g., `/usr/local/go/bin/go`).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```
2.  **Download Dependencies:**
    ```bash
    /usr/local/go/bin/go mod download
    ```

## Configuration

This example uses hardcoded configuration values and `compose.Compose` for setting up Fosite.

*   **Fosite Setup:** Uses `compose.Compose` with `compose.CommonStrategy` (`main.go`).
*   **HMAC Secret:** A 32-byte secret (`jwtSecret`) is defined and set in `fositeConfig.GlobalSecret`. The core HMAC strategy (`CoreStrategy`) is configured via `compose.NewOAuth2HMACStrategy(fositeConfig)`, relying on the `GlobalSecret`. **Use a strong, random secret in production.**
*   **OIDC Strategy:** Uses RSA keys (generated on startup) configured via `compose.NewOpenIDConnectStrategy(...)` within `CommonStrategy`. **Use persistent, securely stored RSA keys in production.**
*   **Storage:** Uses an in-memory store (`storage.go`). All data is lost on restart. **Replace with persistent storage (SQL, etc.) for production.**
*   **Example Client:** Client ID `my-test-client`, secret `foobar` (hashed in `storage.go`).
*   **Port:** Listens on `:8080` (`main.go`).
*   **Session Management:** Basic, insecure in-memory sessions (`handlers.go`). **Replace with robust session handling.**
*   **CSRF Protection:** Currently uses manual token checking. The `gorilla/csrf` import is commented out. **Needs proper middleware implementation.**

## Running the Server

```bash
/usr/local/go/bin/go run .
```
The server will start listening on `http://localhost:8080`.

## Running with Docker

Alternatively, you can build and run the application using Docker, avoiding the need to install Go dependencies locally.

1.  **Build the Docker Image:**
    ```bash
    docker build -t identity-go-app .
    ```
    This command builds the Docker image using the `Dockerfile` in the root directory and tags it as `identity-go-app`.

2.  **Run the Docker Container:**
    ```bash
    docker run -p 8080:8080 identity-go-app
    ```
    This command starts a container from the `identity-go-app` image and maps port 8080 on your host machine to port 8080 inside the container.

    The server will start listening, and you can access it at `http://localhost:8080` in your browser.

## Endpoints

*   `/oauth2/auth`: Authorization endpoint.
*   `/oauth2/token`: Token endpoint.
*   `/oauth2/introspect`: Token introspection endpoint.
*   `/oauth2/revoke`: Token revocation endpoint.
*   `/login`: Login form.
*   `/consent`: Consent form.
*   `/.well-known/openid-configuration`: (Currently Commented Out).
*   `/.well-known/jwks.json`: (Currently Commented Out).

## Example Usage (curl)

These examples use `curl` to interact with the API endpoints. Replace placeholders like `<CODE>`, `<ACCESS_TOKEN>`, `<REFRESH_TOKEN>`.

**Note:** `/oauth2/auth`, `/login`, `/consent` require browser interaction.

### 1. Authorization Request (Browser Flow Start)

Open in browser:
```
http://localhost:8080/oauth2/auth?response_type=code&client_id=my-test-client&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email%20offline&state=some-random-state-123
```
*(After login/consent, browser redirects to `http://localhost:3000/callback?code=<CODE>&state=...`)*

### 2. Token Exchange (Authorization Code Grant)

Exchange the `CODE` from step 1:

```bash
curl -X POST http://localhost:8080/oauth2/token \
-u "my-test-client:foobar" \
-d "grant_type=authorization_code" \
-d "code=<CODE>" \
-d "redirect_uri=http://localhost:3000/callback"
```

*Example Success Response (JSON):*
```json
{
  "access_token": "...",
  "expires_in": 1800,
  "id_token": "...",
  "refresh_token": "...",
  "scope": "openid profile email offline",
  "token_type": "bearer"
}
```

### 3. Token Exchange (Client Credentials Grant)

Request an access token using client credentials.

```bash
curl -X POST http://localhost:8080/oauth2/token \
-u "my-test-client:foobar" \
-d "grant_type=client_credentials" \
-d "scope=openid profile"
```

*Example Success Response (JSON):*
```json
{
  "access_token": "ory_at_...",
  "expires_in": 1799,
  "scope": "openid profile",
  "token_type": "bearer"
}
```
*(Note: The exact access_token value will vary. Scope might differ based on client configuration.)*

### 4. Token Refresh

```bash
curl -X POST http://localhost:8080/oauth2/token \
-u "my-test-client:foobar" \
-d "grant_type=refresh_token" \
-d "refresh_token=<REFRESH_TOKEN>"
```

*Example Success Response (JSON):*
```json
{
  "access_token": "(new)...",
  "expires_in": 1800,
  "id_token": "(potentially new)...",
  "refresh_token": "(potentially new)...",
  "scope": "openid profile email offline",
  "token_type": "bearer"
}
```

### 5. Token Introspection

```bash
curl -X POST http://localhost:8080/oauth2/introspect \
-u "my-test-client:foobar" \
-d "token=<ACCESS_TOKEN>"
```

*Example Success Response (Active - JSON):*
```json
{
  "active": true,
  "aud": ["https://my-api.com"],
  "client_id": "my-test-client",
  "exp": ..., "iat": ..., "iss": "http://localhost:8080", "jti": "...", "nbf": ...,
  "scope": "openid profile email offline",
  "sub": "user-id...",
  "token_type": "access_token",
  "username": "user-id..."
}
```

*Example Success Response (Inactive - JSON):*
```json
{"active": false}
```

### 6. Token Revocation

```bash
curl -X POST http://localhost:8080/oauth2/revoke \
-u "my-test-client:foobar" \
-d "token=<ACCESS_TOKEN_OR_REFRESH_TOKEN>"
```

*Example Success Response (Status 200 OK - No Content)*

## Testing

Unit tests are provided in `main_test.go`. You can run them using:

```bash
/usr/local/go/bin/go test -v
```

**Current Test Coverage (Happy Paths):**

*   Client Credentials Grant (`TestClientCredentialsFlow`)
*   Authorization Code Token Exchange (`TestAuthorizationCodeTokenExchange`)
*   Token Introspection (Successful) (`TestTokenIntrospection`)
*   Login Form Submission (`TestLoginHandler`)
*   Consent Form Submission (Allow) (`TestConsentHandler`)

**Testing TODOs & Limitations:**

*   **Full Authorization Code Flow:** Test the complete sequence including redirects and handler interactions.
*   **Refresh Token Flow:** Add test for the `refresh_token` grant type.
*   **Token Revocation Verification:** The current `TestTokenRevocation` passes but confirms revocation is *broken* with the current `InMemoryStore` (token not deleted). Needs a test that verifies *successful* revocation (requires fixing storage).
*   **Introspection Failure Cases:** Test introspection for invalid, expired, or properly revoked tokens (`active: false`).
*   **Login/Consent GET Handlers:** Test rendering of the HTML forms.
*   **Login/Consent Failure Cases:** Test invalid credentials, invalid CSRF token, consent denial.
*   **API Error Handling:** Test invalid requests (client ID/secret, code, redirect URI, scope) to API endpoints.
*   **Isolate Global State:** Refactor tests/session handling to avoid relying on the global `sessions` map.
*   **CSRF Middleware Testing:** Update tests after implementing `gorilla/csrf`.
*   **OIDC/JWKS/PKCE Testing:** Add tests when these features are uncommented/implemented.
*   **Storage Interactions:** More detailed tests focusing specifically on the storage methods could be added, especially when moving to persistent storage.

## Current Limitations & Future Work

*   **In-Memory Storage:** Not suitable for production.
*   **Basic Session Handling:** Insecure.
*   **No Proper CSRF Middleware:** Manual CSRF logic in place; `gorilla/csrf` not used.
*   **OIDC Discovery & JWKS Missing:** Handlers are commented out.
*   **Hardcoded Configuration:** Secrets and client details are hardcoded.
*   **Limited User Management:** Only a dummy user (`user`/`password`) check exists.

Future work includes addressing these limitations.