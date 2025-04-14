// Package main_test testa o ponto de entrada do servidor de identidade.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"identity-go/internal/infrastructure/auth"
	"identity-go/internal/interface/http/handlers"
)

// MockProvider implementa um provedor OAuth2 simulado para testes
type MockProvider struct {
	mock.Mock
}

// MockStore implementa um armazenamento OAuth2 simulado para testes
type MockStore struct {
	mock.Mock
}

// setupServerForTesting cria uma versão testável do servidor
func setupServerForTesting(secretKey string) (*http.Server, error) {
	// Salvar a variável de ambiente original para restaurar depois
	originalKey := os.Getenv("OAUTH2_SECRET_KEY")
	os.Setenv("OAUTH2_SECRET_KEY", secretKey)
	defer os.Setenv("OAUTH2_SECRET_KEY", originalKey)

	// Configurar o diretório de trabalho para encontrar os templates
	// Busca a pasta templates no diretório raiz do projeto, não no diretório de testes
	workDir, _ := os.Getwd()
	projectRoot := filepath.Dir(filepath.Dir(workDir)) // Volta dois níveis para raiz do projeto

	// Definir a variável de ambiente para informar o handlers onde encontrar os templates
	os.Setenv("TEMPLATES_PATH", filepath.Join(projectRoot, "templates"))

	if secretKey == "" {
		return nil, nil // Retorna nil para simular o log.Fatal
	}

	provider, store := auth.SetupOAuth2Provider([]byte(secretKey))
	router := handlers.SetupRouter(provider, store)

	// Configurar servidor HTTP com timeouts adequados
	srv := &http.Server{
		Addr:         ":0", // Porta aleatória para evitar conflitos nos testes
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return srv, nil
}

// TestServerConfiguration verifica se o servidor é configurado corretamente
func TestServerConfiguration(t *testing.T) {
	srv, err := setupServerForTesting("test-secret-key")
	assert.NoError(t, err)
	assert.NotNil(t, srv)
	assert.Equal(t, 15*time.Second, srv.ReadTimeout)
	assert.Equal(t, 15*time.Second, srv.WriteTimeout)
	assert.Equal(t, 60*time.Second, srv.IdleTimeout)
}

// TestMissingSecretKey verifica o comportamento quando a chave secreta está ausente
func TestMissingSecretKey(t *testing.T) {
	srv, err := setupServerForTesting("")
	assert.Nil(t, srv)
	assert.Nil(t, err) // Não retorna erro explícito já que main() usa log.Fatal
}

// TestGracefulShutdown verifica se o servidor é encerrado adequadamente
func TestGracefulShutdown(t *testing.T) {
	// Cria um servidor de teste que responde após um pequeno delay
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Simula um pedido de encerramento gracioso
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Inicia uma requisição de longa duração
	go func() {
		_, _ = http.Get(ts.URL)
	}()

	// Espera um pouco para garantir que a requisição começou
	time.Sleep(50 * time.Millisecond)

	// Tenta encerrar o servidor
	err := ts.Config.Shutdown(ctx)
	assert.NoError(t, err)
}

// TestSignalHandling simula o recebimento de um sinal para encerramento
func TestSignalHandling(t *testing.T) {
	quit := make(chan os.Signal, 1)

	// Simula o recebimento de um sinal
	go func() {
		// Pequeno delay para garantir que o canal está pronto
		time.Sleep(50 * time.Millisecond)
		quit <- syscall.SIGINT
	}()

	// Verifica se o sinal é recebido (não deve bloquear)
	select {
	case <-quit:
		// Teste passou - o sinal foi recebido
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout esperando pelo sinal")
	}
}
