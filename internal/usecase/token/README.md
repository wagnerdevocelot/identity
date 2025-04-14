# Token Use Cases

## Descrição

Este diretório contém os casos de uso relacionados ao gerenciamento de tokens OAuth2 e OpenID Connect. Implementa os diferentes fluxos de concessão de tokens, validação, revogação e atualização.

## Responsabilidades

- Implementar os fluxos OAuth2 e OpenID Connect
- Gerenciar ciclo de vida dos tokens (geração, validação, revogação)
- Aplicar regras de negócio específicas para cada tipo de token
- Coordenar interações entre serviços de domínio e repositórios

## Principais Casos de Uso

- `GenerateTokenUseCase`: Cria tokens conforme o fluxo de concessão (authorization code, client credentials, etc)
- `ValidateTokenUseCase`: Valida tokens e extrai suas informações
- `RefreshTokenUseCase`: Implementa o fluxo de renovação de tokens usando refresh tokens
- `RevokeTokenUseCase`: Gerencia a revogação de tokens
- `IntrospectTokenUseCase`: Implementa a introspection de tokens conforme RFC 7662

## Princípios de Design

- Implementar cada fluxo de token como um caso de uso separado
- Delegar operações criptográficas e de validação para serviços do domínio
- Manter a conformidade com os padrões OAuth2 e OpenID Connect
- Utilizar injeção de dependência para acessar repositórios e serviços