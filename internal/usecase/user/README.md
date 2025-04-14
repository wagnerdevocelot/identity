# User Use Cases

## Descrição

Este diretório contém os casos de uso relacionados ao gerenciamento de usuários no sistema de identidade. Implementa operações como criação, atualização, busca e remoção de usuários, além de operações específicas como gerenciamento de perfis.

## Responsabilidades

- Implementar a lógica de gerenciamento do ciclo de vida de usuários
- Orquestrar operações CRUD para usuários
- Implementar fluxos específicos como alteração de perfil ou atualização de dados
- Coordenar interações entre serviços de domínio e repositórios

## Principais Casos de Uso

- `CreateUserUseCase`: Gerencia a criação de novos usuários no sistema
- `UpdateUserUseCase`: Implementa a atualização de dados de usuários
- `FindUserUseCase`: Busca usuários por diferentes critérios
- `DeleteUserUseCase`: Gerencia a remoção de usuários
- `UpdateProfileUseCase`: Implementa atualização de perfil do usuário
- `ChangePasswordUseCase`: Gerencia o fluxo de alteração de senha

## Princípios de Design

- Cada caso de uso deve ter responsabilidade única
- A validação de dados deve ser realizada tanto no nível de entidade quanto no caso de uso
- Delegar operações de persistência para repositórios
- Utilizar injeção de dependência para acessar repositórios e serviços
- Implementar tratamento de erros adequado para feedback ao usuário