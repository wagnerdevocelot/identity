# HTTP Controllers

## Descrição

Este diretório contém os controladores HTTP responsáveis por receber e processar requisições web, interagir com casos de uso e retornar respostas apropriadas. Os controladores são a porta de entrada principal da API REST do sistema de identidade.

## Responsabilidades

- Receber requisições HTTP
- Validar entrada de dados e parâmetros de requisição
- Traduzir requisições em chamadas para casos de uso apropriados
- Converter resultados dos casos de uso em respostas HTTP
- Gerenciar códigos de status e headers de resposta
- Implementar tratamento de erros e exceções

## Principais Controladores

- `AuthController`: Gerencia endpoints de autenticação como login, logout, registro
- `TokenController`: Implementa endpoints OAuth2 como token, introspection, revoke
- `UserController`: Gerencia endpoints CRUD para usuários
- `ConsentController`: Gerencia endpoints relacionados ao consentimento do usuário
- `HealthController`: Endpoints de healthcheck e status da aplicação

## Princípios de Design

- Controladores devem ser pequenos e focados em tradução de protocolo
- A lógica de negócio deve permanecer nos casos de uso
- Utilizar middleware para funcionalidades transversais como autenticação, logging, etc.
- Implementar validação de entrada para garantir dados consistentes
- Seguir padrões RESTful para design de API
- Documentar endpoints com OpenAPI/Swagger