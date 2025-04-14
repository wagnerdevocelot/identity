# Domain Services

## Descrição

Este diretório contém as interfaces dos serviços de domínio que definem operações que não se encaixam naturalmente em uma única entidade. Os serviços de domínio implementam lógica de negócio que coordena múltiplas entidades ou representa processos complexos do domínio.

## Responsabilidades

- Definir interfaces para operações de negócio complexas
- Orquestrar interações entre múltiplas entidades
- Encapsular regras de negócio que não pertencem a uma única entidade
- Estabelecer contratos claros entre o domínio e as camadas externas

## Interfaces Principais

- `AuthenticationService`: Responsável por operações de autenticação
- `AuthorizationService`: Gerencia autorizações e verificações de permissões
- `TokenService`: Define operações de geração e validação de tokens
- `ConsentService`: Gerencia consentimentos de usuário para acesso a recursos

## Princípios de Design

- Serviços devem ter responsabilidade única e coesa
- As interfaces devem ser definidas em termos do domínio, não de tecnologia
- Os serviços devem ser stateless sempre que possível
- Evitar lógica de domínio nas implementações de caso de uso