package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// failingStore wraps InMemoryStore and allows forcing errors for selected methods.
type failingStore struct {
	*InMemoryStore
	fail map[string]bool
}

func newFailingStore(fail map[string]bool) *failingStore {
	return &failingStore{InMemoryStore: NewInMemoryStore(), fail: fail}
}

func (s *failingStore) shouldFail(method string) bool { return s.fail[method] }

func (s *failingStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	if s.shouldFail("GetClient") {
		return nil, errors.New("fail")
	}
	return s.InMemoryStore.GetClient(ctx, id)
}
func (s *failingStore) CreateClient(ctx context.Context, c fosite.Client) error {
	if s.shouldFail("CreateClient") {
		return errors.New("fail")
	}
	return s.InMemoryStore.CreateClient(ctx, c)
}
func (s *failingStore) UpdateClient(ctx context.Context, c fosite.Client) error {
	if s.shouldFail("UpdateClient") {
		return errors.New("fail")
	}
	return s.InMemoryStore.UpdateClient(ctx, c)
}
func (s *failingStore) DeleteClient(ctx context.Context, id string) error {
	if s.shouldFail("DeleteClient") {
		return errors.New("fail")
	}
	return s.InMemoryStore.DeleteClient(ctx, id)
}
func (s *failingStore) CreateToken(ctx context.Context, tokenType, signature, clientID string, data interface{}) error {
	if s.shouldFail("CreateToken") {
		return errors.New("fail")
	}
	return s.InMemoryStore.CreateToken(ctx, tokenType, signature, clientID, data)
}
func (s *failingStore) GetToken(ctx context.Context, tokenType, signature string) (interface{}, error) {
	if s.shouldFail("GetToken") {
		return nil, errors.New("fail")
	}
	return s.InMemoryStore.GetToken(ctx, tokenType, signature)
}
func (s *failingStore) DeleteToken(ctx context.Context, tokenType, signature string) error {
	if s.shouldFail("DeleteToken") {
		return errors.New("fail")
	}
	return s.InMemoryStore.DeleteToken(ctx, tokenType, signature)
}
func (s *failingStore) RevokeToken(ctx context.Context, tokenType, signature string) error {
	if s.shouldFail("RevokeToken") {
		return errors.New("fail")
	}
	return s.InMemoryStore.RevokeToken(ctx, tokenType, signature)
}
func (s *failingStore) CreateSession(ctx context.Context, sessionType, id string, data interface{}) error {
	if s.shouldFail("CreateSession") {
		return errors.New("fail")
	}
	return s.InMemoryStore.CreateSession(ctx, sessionType, id, data)
}
func (s *failingStore) GetSession(ctx context.Context, sessionType, id string) (interface{}, error) {
	if s.shouldFail("GetSession") {
		return nil, errors.New("fail")
	}
	return s.InMemoryStore.GetSession(ctx, sessionType, id)
}
func (s *failingStore) DeleteSession(ctx context.Context, sessionType, id string) error {
	if s.shouldFail("DeleteSession") {
		return errors.New("fail")
	}
	return s.InMemoryStore.DeleteSession(ctx, sessionType, id)
}
func (s *failingStore) ValidateJWT(ctx context.Context, jti string) error {
	if s.shouldFail("ValidateJWT") {
		return errors.New("fail")
	}
	return s.InMemoryStore.ValidateJWT(ctx, jti)
}
func (s *failingStore) MarkJWTAsUsed(ctx context.Context, jti string, exp time.Time) error {
	if s.shouldFail("MarkJWTAsUsed") {
		return errors.New("fail")
	}
	return s.InMemoryStore.MarkJWTAsUsed(ctx, jti, exp)
}
func (s *failingStore) GetPKCERequestSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	if s.shouldFail("GetPKCERequestSession") {
		return nil, errors.New("fail")
	}
	return s.InMemoryStore.GetPKCERequestSession(ctx, signature, sess)
}
func (s *failingStore) CreatePKCERequestSession(ctx context.Context, signature string, r fosite.Requester) error {
	if s.shouldFail("CreatePKCERequestSession") {
		return errors.New("fail")
	}
	return s.InMemoryStore.CreatePKCERequestSession(ctx, signature, r)
}
func (s *failingStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	if s.shouldFail("DeletePKCERequestSession") {
		return errors.New("fail")
	}
	return s.InMemoryStore.DeletePKCERequestSession(ctx, signature)
}

func TestLoggingAdapterMetrics(t *testing.T) {
	ctx := context.Background()
	adapter := NewLoggingAdapter(NewInMemoryStore())

	c := &fosite.DefaultClient{ID: "c1"}
	if err := adapter.CreateClient(ctx, c); err != nil {
		t.Fatalf("CreateClient err: %v", err)
	}
	if _, err := adapter.GetClient(ctx, "c1"); err != nil {
		t.Fatalf("GetClient err: %v", err)
	}
	if err := adapter.UpdateClient(ctx, c); err != nil {
		t.Fatalf("UpdateClient err: %v", err)
	}
	if err := adapter.DeleteClient(ctx, "c1"); err != nil {
		t.Fatalf("DeleteClient err: %v", err)
	}

	req := &fosite.Request{}
	if err := adapter.CreateToken(ctx, "access_token", "sig", "c1", req); err != nil {
		t.Fatalf("CreateToken err: %v", err)
	}
	if _, err := adapter.GetToken(ctx, "access_token", "sig"); err != nil {
		t.Fatalf("GetToken err: %v", err)
	}
	if err := adapter.RevokeToken(ctx, "access_token", "sig"); err != nil {
		t.Fatalf("RevokeToken err: %v", err)
	}
	if err := adapter.DeleteToken(ctx, "access_token", "sig"); err != nil {
		t.Fatalf("DeleteToken err: %v", err)
	}

	if err := adapter.CreateSession(ctx, "openid", "s1", req); err != nil {
		t.Fatalf("CreateSession err: %v", err)
	}
	if _, err := adapter.GetSession(ctx, "openid", "s1"); err != nil {
		t.Fatalf("GetSession err: %v", err)
	}
	if err := adapter.DeleteSession(ctx, "openid", "s1"); err != nil {
		t.Fatalf("DeleteSession err: %v", err)
	}

	if err := adapter.ValidateJWT(ctx, "j1"); err != nil {
		t.Fatalf("ValidateJWT err: %v", err)
	}
	if err := adapter.MarkJWTAsUsed(ctx, "j1", time.Now()); err != nil {
		t.Fatalf("MarkJWTAsUsed err: %v", err)
	}

	if err := adapter.CreatePKCERequestSession(ctx, "p1", req); err != nil {
		t.Fatalf("CreatePKCERequestSession err: %v", err)
	}
	if _, err := adapter.GetPKCERequestSession(ctx, "p1", &openid.DefaultSession{}); err != nil {
		t.Fatalf("GetPKCERequestSession err: %v", err)
	}
	if err := adapter.DeletePKCERequestSession(ctx, "p1"); err != nil {
		t.Fatalf("DeletePKCERequestSession err: %v", err)
	}

	metrics := adapter.Metrics()
	expected := []string{"CreateClient", "GetClient", "UpdateClient", "DeleteClient", "CreateToken", "GetToken", "RevokeToken", "DeleteToken", "CreateSession", "GetSession", "DeleteSession", "ValidateJWT", "MarkJWTAsUsed", "CreatePKCESession", "GetPKCESession", "DeletePKCESession"}
	for _, m := range expected {
		if metrics[m] == 0 {
			t.Errorf("metric %s not incremented", m)
		}
	}
}

func TestLoggingAdapterErrorMetrics(t *testing.T) {
	ctx := context.Background()
	fs := newFailingStore(map[string]bool{"GetClient": true})
	adapter := NewLoggingAdapter(fs)
	if _, err := adapter.GetClient(ctx, "x"); err == nil {
		t.Fatal("expected error")
	}
	if adapter.Metrics()["GetClientError"] != 1 {
		t.Errorf("error metric not incremented")
	}
}
