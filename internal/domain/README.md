# Domain Layer

## Responsabilidade

O diretório `domain` contém as entidades e regras de negócio centrais do sistema de identidade. Esta camada define os objetos de domínio fundamentais e as interfaces de repositório necessárias para manipular esses objetos.

### Princípios

- Não depende de nenhuma outra camada
- Contém as regras de negócio e entidades principais
- Define interfaces para repositórios e serviços que serão implementados em outras camadas
- Não contém detalhes de implementação (bancos de dados, frameworks, etc.)

### Estrutura

- `/entity`: Definição das entidades e objetos de valor do domínio
- `/repository`: Interfaces dos repositórios para persistência de dados
- `/service`: Interfaces para serviços de domínio e operações de negócio

### Exemplo de Entidades

- User
- Client
- Session
- Token
- Scope

Esta camada deve ser estável e mudar apenas quando as regras de negócio centrais mudam.