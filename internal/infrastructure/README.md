# Infrastructure Layer

## Responsabilidade

O diretório `infrastructure` contém implementações concretas de interfaces definidas nas camadas de domínio e caso de uso, além de código que lida com frameworks externos, bancos de dados, serviços de terceiros, e outros detalhes técnicos.

### Princípios

- Implementa interfaces definidas nas camadas de domínio e caso de uso
- Contém código específico de tecnologia e frameworks
- Lida com detalhes técnicos como persistência, autenticação, comunicação externa
- É a camada mais propensa a mudanças devido a alterações tecnológicas

### Estrutura

- `/storage`: Implementações de repositórios para persistência de dados
- `/auth`: Implementações concretas de serviços de autenticação/autorização
- `/config`: Configurações de aplicação e ambiente

### Exemplos de Componentes

- InMemoryRepository
- SQLRepository
- OAuthProvider
- JWTService
- ConfigManager

Esta camada contém a "cola" técnica que permite que a lógica do negócio seja executada em ambientes reais. Alterações nesta camada (como mudar um banco de dados) não devem impactar as camadas de domínio e caso de uso.