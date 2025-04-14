# Domain Repositories

## Descrição

Este diretório contém as interfaces dos repositórios que definem como as entidades do domínio serão persistidas e recuperadas. Os repositórios são abstrações que isolam o domínio dos detalhes de infraestrutura de armazenamento.

## Responsabilidades

- Definir contratos (interfaces) para operações de persistência
- Estabelecer métodos para busca, criação, atualização e remoção de entidades
- Isolar o domínio dos detalhes de implementação de armazenamento
- Permitir troca transparente de mecanismos de armazenamento

## Interfaces Principais

- `UserRepository`: Operações de persistência para usuários
- `ClientRepository`: Operações de persistência para clientes OAuth2
- `TokenRepository`: Operações para armazenar e recuperar tokens
- `SessionRepository`: Gerenciamento de sessões de usuário
- `ScopeRepository`: Gerenciamento de escopos de permissão

## Princípios de Design

- Interfaces devem ser definidas em termos do domínio, não da tecnologia
- As interfaces não devem expor detalhes de implementação de banco de dados
- Os métodos devem receber e retornar entidades de domínio, não DTOs
- A nomenclatura deve seguir a linguagem ubíqua do domínio