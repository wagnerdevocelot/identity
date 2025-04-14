# Usecase Layer

## Responsabilidade

O diretório `usecase` contém a implementação dos casos de uso da aplicação, que representam as operações específicas que o sistema pode realizar. Esta camada orquestra o fluxo de dados entre as entidades do domínio e as interfaces externas.

### Princípios

- Depende apenas da camada de domínio
- Implementa a lógica de aplicação específica para cada caso de uso
- Coordena as entidades de domínio para executar operações de negócio
- Não contém regras de negócio específicas de entidades (estas pertencem ao domínio)
- Não lida com detalhes de UI, banco de dados ou frameworks externos

### Estrutura

- `/auth`: Casos de uso relacionados à autenticação e autorização
- `/token`: Casos de uso para gerenciamento de tokens OAuth2/OpenID Connect
- `/user`: Casos de uso para gerenciamento de usuários

### Exemplos de Casos de Uso

- LoginUsecase
- GenerateTokenUsecase
- ValidateTokenUsecase
- UserRegistrationUsecase
- ConsentManagementUsecase

Esta camada implementa os fluxos de trabalho específicos da aplicação e pode mudar quando os requisitos da aplicação são alterados, sem necessariamente alterar as entidades do domínio.