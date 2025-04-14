// Package main é o ponto de entrada do servidor de identidade.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"identity-go/internal/infrastructure/auth"
	"identity-go/internal/interface/http/handlers"
)

func main() {
	log.Println("Iniciando servidor de identidade na porta 8080...")

	// Carregar a chave secreta do ambiente (exemplo)
	secretKey := os.Getenv("OAUTH2_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("Variável de ambiente OAUTH2_SECRET_KEY não definida")
	}

	// Configurar provedor OAuth2 e armazenamento
	provider, store := auth.SetupOAuth2Provider([]byte(secretKey))

	// Configurar router HTTP com todos os handlers
	router := handlers.SetupRouter(provider, store)

	// Configurar servidor HTTP com timeouts adequados
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Iniciar servidor em uma goroutine separada
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Erro ao iniciar servidor: %s\n", err)
		}
	}()

	log.Println("Servidor rodando. Pressione CTRL+C para desligar.")

	// Canal para receber sinais de interrupção
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Bloquear até receber sinal
	<-quit

	log.Println("Desligando servidor graciosamente...")

	// Criar contexto com timeout para shutdown gracioso
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Tentar shutdown gracioso
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Erro durante o desligamento do servidor: %v", err)
	}

	log.Println("Servidor desligado com sucesso")
}
