package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
)

// LoggingAdapter wraps another StorageInterface and logs all operations.
// fullStorage groups all interfaces required by fosite's Compose plus our
// generic StorageInterface. Any real backend (memory or DB) should implement
// all of them.
type fullStorage interface {
	fosite.Storage
	openid.OpenIDConnectRequestStorage
	oauth2.CoreStorage
	oauth2.TokenRevocationStorage
	pkce.PKCERequestStorage
	StorageInterface
}

// LoggingAdapter wraps another storage backend and records metrics while
// delegating all operations to it.
type LoggingAdapter struct {
	fullStorage
	mu      sync.Mutex
	metrics map[string]int
}

// NewLoggingAdapter creates a new adapter with the given backend.
func NewLoggingAdapter(backend fullStorage) *LoggingAdapter {
	return &LoggingAdapter{fullStorage: backend, metrics: make(map[string]int)}
}

func (l *LoggingAdapter) inc(key string) {
	l.mu.Lock()
	l.metrics[key]++
	l.mu.Unlock()
}

// Metrics returns a copy of collected metrics.
func (l *LoggingAdapter) Metrics() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	copy := make(map[string]int, len(l.metrics))
	for k, v := range l.metrics {
		copy[k] = v
	}
	return copy
}

func (l *LoggingAdapter) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	operation := func() (interface{}, error) {
		return l.fullStorage.GetClient(ctx, id)
	}
	result, err := l.logAndIncrementMetrics(
		ctx,
		operation,
		"GetClient",
		"GetClientError",
		"logging adapter: GetClient %s failed: %v",
	)
	return result.(fosite.Client), err
}

func (l *LoggingAdapter) CreateClient(ctx context.Context, client fosite.Client) error {
	operation := func() (interface{}, error) {
		return nil, l.fullStorage.CreateClient(ctx, client)
	}
	_, err := l.logAndIncrementMetrics(
		ctx,
		operation,
		"CreateClient",
		"CreateClientError",
		"logging adapter: CreateClient %s failed: %v",
	)
	return err
}

func (l *LoggingAdapter) UpdateClient(ctx context.Context, client fosite.Client) error {
	err := l.fullStorage.UpdateClient(ctx, client)
	if err != nil {
		log.Printf("logging adapter: UpdateClient %s failed: %v", client.GetID(), err)
		l.inc("UpdateClientError")
	} else {
		l.inc("UpdateClient")
	}
	return err
}

func (l *LoggingAdapter) DeleteClient(ctx context.Context, id string) error {
	err := l.fullStorage.DeleteClient(ctx, id)
	if err != nil {
		log.Printf("logging adapter: DeleteClient %s failed: %v", id, err)
		l.inc("DeleteClientError")
	} else {
		l.inc("DeleteClient")
	}
	return err
}

func (l *LoggingAdapter) CreateToken(ctx context.Context, tokenType, signature, clientID string, data interface{}) error {
	err := l.fullStorage.CreateToken(ctx, tokenType, signature, clientID, data)
	if err != nil {
		log.Printf("logging adapter: CreateToken %s failed: %v", tokenType, err)
		l.inc("CreateTokenError")
	} else {
		l.inc("CreateToken")
	}
	return err
}

func (l *LoggingAdapter) GetToken(ctx context.Context, tokenType, signature string) (interface{}, error) {
	v, err := l.fullStorage.GetToken(ctx, tokenType, signature)
	if err != nil {
		log.Printf("logging adapter: GetToken %s failed: %v", tokenType, err)
		l.inc("GetTokenError")
	} else {
		l.inc("GetToken")
	}
	return v, err
}

func (l *LoggingAdapter) DeleteToken(ctx context.Context, tokenType, signature string) error {
	err := l.fullStorage.DeleteToken(ctx, tokenType, signature)
	if err != nil {
		log.Printf("logging adapter: DeleteToken %s failed: %v", tokenType, err)
		l.inc("DeleteTokenError")
	} else {
		l.inc("DeleteToken")
	}
	return err
}

func (l *LoggingAdapter) RevokeToken(ctx context.Context, tokenType, signature string) error {
	err := l.fullStorage.RevokeToken(ctx, tokenType, signature)
	if err != nil {
		log.Printf("logging adapter: RevokeToken %s failed: %v", tokenType, err)
		l.inc("RevokeTokenError")
	} else {
		l.inc("RevokeToken")
	}
	return err
}

func (l *LoggingAdapter) CreateSession(ctx context.Context, sessionType, id string, data interface{}) error {
	err := l.fullStorage.CreateSession(ctx, sessionType, id, data)
	if err != nil {
		log.Printf("logging adapter: CreateSession %s failed: %v", sessionType, err)
		l.inc("CreateSessionError")
	} else {
		l.inc("CreateSession")
	}
	return err
}

func (l *LoggingAdapter) GetSession(ctx context.Context, sessionType, id string) (interface{}, error) {
	v, err := l.fullStorage.GetSession(ctx, sessionType, id)
	if err != nil {
		log.Printf("logging adapter: GetSession %s failed: %v", sessionType, err)
		l.inc("GetSessionError")
	} else {
		l.inc("GetSession")
	}
	return v, err
}

func (l *LoggingAdapter) DeleteSession(ctx context.Context, sessionType, id string) error {
	err := l.fullStorage.DeleteSession(ctx, sessionType, id)
	if err != nil {
		log.Printf("logging adapter: DeleteSession %s failed: %v", sessionType, err)
		l.inc("DeleteSessionError")
	} else {
		l.inc("DeleteSession")
	}
	return err
}

func (l *LoggingAdapter) ValidateJWT(ctx context.Context, jti string) error {
	err := l.fullStorage.ValidateJWT(ctx, jti)
	if err != nil {
		log.Printf("logging adapter: ValidateJWT failed: %v", err)
		l.inc("ValidateJWTError")
	} else {
		l.inc("ValidateJWT")
	}
	return err
}

func (l *LoggingAdapter) MarkJWTAsUsed(ctx context.Context, jti string, exp time.Time) error {
	err := l.fullStorage.MarkJWTAsUsed(ctx, jti, exp)
	if err != nil {
		log.Printf("logging adapter: MarkJWTAsUsed failed: %v", err)
		l.inc("MarkJWTAsUsedError")
	} else {
		l.inc("MarkJWTAsUsed")
	}
	return err
}

func (l *LoggingAdapter) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	v, err := l.fullStorage.GetPKCERequestSession(ctx, signature, session)
	if err != nil {
		log.Printf("logging adapter: GetPKCERequestSession failed: %v", err)
		l.inc("GetPKCESessionError")
	} else {
		l.inc("GetPKCESession")
	}
	return v, err
}

func (l *LoggingAdapter) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	err := l.fullStorage.CreatePKCERequestSession(ctx, signature, requester)
	if err != nil {
		log.Printf("logging adapter: CreatePKCERequestSession failed: %v", err)
		l.inc("CreatePKCESessionError")
	} else {
		l.inc("CreatePKCESession")
	}
	return err
}

func (l *LoggingAdapter) DeletePKCERequestSession(ctx context.Context, signature string) error {
	err := l.fullStorage.DeletePKCERequestSession(ctx, signature)
	if err != nil {
		log.Printf("logging adapter: DeletePKCERequestSession failed: %v", err)
		l.inc("DeletePKCESessionError")
	} else {
		l.inc("DeletePKCESession")
	}
	return err
}
