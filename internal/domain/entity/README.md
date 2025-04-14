# Domain Entities

## Descrição

Este diretório contém as entidades do domínio, que são os objetos centrais do modelo de negócio da aplicação de identidade. As entidades representam os conceitos fundamentais do sistema e encapsulam os dados e comportamentos essenciais.

## Responsabilidades

- Definir os objetos centrais do domínio de negócio
- Encapsular estado e comportamento relacionados a cada entidade
- Implementar regras de negócio intrínsecas às entidades
- Manter independência de frameworks e detalhes técnicos

## Entidades Principais

- `User`: Representa um usuário do sistema com suas credenciais e dados pessoais
- `Client`: Representa uma aplicação cliente que utiliza o serviço de identidade
- `Token`: Representa tokens de acesso, refresh e ID gerados pelo sistema
- `Session`: Representa uma sessão de usuário autenticado
- `Scope`: Representa permissões específicas que podem ser concedidas

## Princípios de Design

- Entidades devem validar seu próprio estado
- Regras de negócio intrínsecas à entidade devem ser implementadas na própria entidade
- Entidades não devem depender de camadas externas
- Utilize Value Objects para encapsular conceitos do domínio que não possuem identidade