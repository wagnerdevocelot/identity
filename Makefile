.PHONY: all build clean test coverage lint run help

# Variáveis
APP_NAME=identity
MAIN_PATH=./cmd/identity
BUILD_DIR=./build
DOCKER_IMAGE=identity-service
GO_FILES=$(shell find . -name "*.go" -type f -not -path "./vendor/*")

# Cores para saída
GREEN=\033[0;32m
YELLOW=\033[0;33m
RESET=\033[0m

# Definição de comandos
all: lint test build

help: ## Mostra a lista de comandos disponíveis
	@echo "Comandos disponíveis:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}'

build: ## Compila a aplicação
	@echo "$(GREEN)Compilando a aplicação...$(RESET)"
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BUILD_DIR)/$(APP_NAME) $(MAIN_PATH)

clean: ## Remove arquivos gerados pela compilação
	@echo "$(GREEN)Limpando o ambiente...$(RESET)"
	@rm -rf $(BUILD_DIR)
	@go clean

test: ## Executa os testes unitários
	@echo "$(GREEN)Executando testes...$(RESET)"
	@go test -v ./...

coverage: ## Executa os testes e gera relatório de cobertura
	@echo "$(GREEN)Gerando relatório de cobertura de testes...$(RESET)"
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Relatório gerado em coverage.html"

lint: ## Executa verificação de código com linter
	@echo "$(GREEN)Executando golangci-lint...$(RESET)"
	@golangci-lint run

fmt: ## Formata o código fonte
	@echo "$(GREEN)Formatando código com gofmt...$(RESET)"
	@gofmt -s -w $(GO_FILES)

run: ## Executa a aplicação
	@echo "$(GREEN)Iniciando a aplicação...$(RESET)"
	@go run $(MAIN_PATH)

docker-build: ## Cria imagem Docker
	@echo "$(GREEN)Criando imagem Docker...$(RESET)"
	@docker build -t $(DOCKER_IMAGE):latest .

docker-run: ## Executa a aplicação em um container Docker
	@echo "$(GREEN)Iniciando container Docker...$(RESET)"
	@docker run -p 8080:8080 --env-file=.env $(DOCKER_IMAGE):latest

migrate-up: ## Executa migrações do banco de dados (up)
	@echo "$(GREEN)Executando migrações do banco de dados (up)...$(RESET)"
	@go run ./cmd/migrate up

migrate-down: ## Reverte migrações do banco de dados (down)
	@echo "$(GREEN)Revertendo migrações do banco de dados (down)...$(RESET)"
	@go run ./cmd/migrate down

proto: ## Gera código a partir dos arquivos protobuf
	@echo "$(GREEN)Gerando código a partir dos arquivos protobuf...$(RESET)"
	@protoc --go_out=. --go-grpc_out=. ./api/proto/*.proto

swagger: ## Gera documentação Swagger
	@echo "$(GREEN)Gerando documentação Swagger...$(RESET)"
	@swag init -g cmd/identity/main.go -o ./internal/interface/api/swagger