# Servidor de Identidade OAuth2/OpenID Connect

Este projeto implementa um servidor de identidade OAuth2 e OpenID Connect usando a biblioteca [ory/fosite](https://github.com/ory/fosite) com uma arquitetura limpa (Clean Architecture).

## Estrutura do Projeto

O projeto segue os princípios da Clean Architecture com uma separação clara de responsabilidades:

```
├── cmd/                    # Pontos de entrada da aplicação
│   └── identity/           # Aplicação principal do servidor de identidade
├── internal/               # Código privado da aplicação
│   ├── domain/             # Entidades e regras de negócio centrais
│   │   ├── entity/         # Definições de entidades do domínio
│   │   ├── repository/     # Interfaces dos repositórios
│   │   └── service/        # Interfaces dos serviços de domínio
│   ├── usecase/            # Casos de uso que orquestram entidades e regras
│   │   ├── auth/           # Casos de uso para autenticação
│   │   ├── token/          # Casos de uso para gerenciamento de tokens
│   │   └── user/           # Casos de uso para gerenciamento de usuários
│   ├── interface/          # Adaptadores de interface externa
│   │   ├── api/            # Definições de API
│   │   ├── http/           # Controladores HTTP
│   │   └── presenter/      # Formatadores de resposta
│   └── infrastructure/     # Implementações concretas e detalhes técnicos
│       ├── auth/           # Implementações de serviços de autenticação
│       ├── config/         # Gerenciamento de configurações
│       └── storage/        # Implementações de repositórios
├── pkg/                    # Código compartilhável como bibliotecas
├── templates/              # Templates HTML para interfaces web
└── Makefile                # Comandos para build, test, etc.
```

## Docker

A aplicação pode ser facilmente executada em contêineres Docker, proporcionando um ambiente isolado e consistente para execução.

### Construção da Imagem Docker

```bash
# Construir a imagem Docker
docker build -t identity-server:latest .
```

### Execução em Contêiner

```bash
# Executar o contêiner expondo a porta 8080
docker run -p 8080:8080 identity-server:latest

# Executar com variáveis de ambiente personalizadas
docker run -p 8080:8080 \
  -e PORT=8080 \
  -e GIN_MODE=release \
  -e TZ=America/Sao_Paulo \
  identity-server:latest
```

### Verificação de Saúde

O contêiner possui uma verificação de integridade (healthcheck) configurada que testa o endpoint `/health` a cada 30 segundos.

### Segurança

A imagem Docker foi construída com várias melhorias de segurança:
- Utilização de multi-stage build para minimizar o tamanho final da imagem
- Execução como usuário não-privilegiado (appuser)
- Remoção de símbolos e informações de debug do binário
- Baseada em Alpine Linux para minimizar a superfície de ataque

## Camadas da Clean Architecture

### 1. Domain (Domínio)

A camada mais interna, contendo as entidades de negócio, interfaces de repositório e interfaces de serviço. Esta camada é independente de frameworks e detalhes de implementação.

### 2. Use Cases (Casos de Uso)

Contém a lógica de aplicação específica, orquestrando entidades para executar operações de negócio. Depende apenas da camada de domínio.

### 3. Interface (Interfaces)

Adapta dados entre os casos de uso e agentes externos. Inclui controladores HTTP, presenters e definições de API.

### 4. Infrastructure (Infraestrutura)

Implementa as interfaces definidas nas camadas internas, fornecendo detalhes técnicos concretos como armazenamento em banco de dados, autenticação e configuração.

## Funcionalidades Principais

- Autenticação de usuários (login/senha)
- Fluxo de autorização OAuth2 (Authorization Code, Client Credentials)
- Integração com OpenID Connect
- Gerenciamento de tokens (geração, validação, revogação)
- Interface web para login e consentimento

## Requisitos

- Go 1.22 ou superior
- Dependências gerenciadas via Go Modules

## Instalação e Execução

```bash
# Clonar o repositório
git clone [URL_DO_REPOSITÓRIO]
cd identity

# Baixar dependências
go mod download

# Compilar
make build

# Executar
make run
```

## Endpoints Principais

- `/oauth2/auth` - Endpoint de autorização
- `/oauth2/token` - Endpoint de token
- `/oauth2/introspect` - Introspecção de token
- `/oauth2/revoke` - Revogação de token
- `/login` - Interface de login
- `/consent` - Interface de consentimento do usuário

## Desenvolvimento

### Comandos Make

- `make build` - Compila a aplicação
- `make run` - Executa a aplicação
- `make test` - Executa os testes unitários
- `make coverage` - Gera relatório de cobertura de testes
- `make lint` - Executa verificação de código com linter
- `make fmt` - Formata o código fonte

### Ambiente de Desenvolvimento

Para desenvolvimento local, o servidor inicia na porta 8080 por padrão e utiliza armazenamento em memória.

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo LICENSE para mais detalhes.