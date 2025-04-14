# Identity Service

## Descrição

Este é o ponto de entrada principal para o serviço de identidade, responsável por iniciar e configurar o servidor OAuth2/OpenID Connect.

## Responsabilidades

- Inicialização da aplicação
- Carregamento de configurações
- Configuração de logging
- Injeção de dependências das diferentes camadas
- Conexão com bancos de dados e serviços externos
- Inicialização do servidor HTTP
- Gerenciamento de ciclo de vida e shutdown gracioso

## Como Executar

```bash
go run cmd/identity/main.go
```

Ou, após compilar:

```bash
./identity
```

## Configuração

O serviço pode ser configurado através de variáveis de ambiente ou arquivo de configuração. Veja a documentação completa em `/internal/infrastructure/config`.