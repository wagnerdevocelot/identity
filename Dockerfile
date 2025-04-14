# Usamos alpine somente para compilação - não estará presente na imagem final
FROM golang:1.22.3-alpine3.19 AS builder

# Instalar ferramentas essenciais para build
RUN apk add --no-cache ca-certificates tzdata git

WORKDIR /build

# Copiar módulos Go e baixar dependências
COPY go.mod go.sum* ./
RUN go mod download && go mod verify

# Copiar todo o código fonte
COPY . .

# Compilar aplicação com flags específicos para segurança
# -trimpath: remove caminhos do sistema de compilação
# CGO_ENABLED=0: gera binário totalmente estático
# ldflags: remove dados de debug e símbolos
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath \
    -ldflags="-w -s -extldflags '-static'" \
    -o /app/identity-go ./cmd/identity

# Imagem final SCRATCH - não contém absolutamente nada além do que copiamos
FROM scratch

# Metadados da imagem
LABEL org.opencontainers.image.title="Identity Server"
LABEL org.opencontainers.image.description="Servidor de identidade OAuth2/OpenID Connect"
LABEL org.opencontainers.image.vendor="Seu Projeto"
LABEL org.opencontainers.image.version="1.0.0"

# Copiar apenas o necessário da imagem de build
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/identity-go /app/identity-go
COPY --from=builder /build/templates /app/templates

# Configuração de ambiente
ENV TZ=America/Sao_Paulo

# Verificação de integridade da aplicação
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/identity-go", "health"] || exit 1

# Diretório de trabalho e porta exposta  
WORKDIR /app
EXPOSE 8080

# Iniciar aplicação
ENTRYPOINT ["/app/identity-go"]