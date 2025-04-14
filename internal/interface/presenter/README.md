# Presenters

## Descrição

Este diretório contém os presenters responsáveis por transformar os dados provenientes dos casos de uso em formatos adequados para apresentação na interface do usuário. Os presenters são a camada de formatação de saída da aplicação.

## Responsabilidades

- Transformar dados de domínio em DTOs (Data Transfer Objects)
- Formatar dados para diferentes tipos de resposta (JSON, XML, HTML, etc.)
- Aplicar transformações específicas de apresentação 
- Garantir consistência na apresentação de dados
- Ocultar detalhes internos desnecessários para a interface do usuário

## Principais Presenters

- `UserPresenter`: Formata dados de usuário para apresentação
- `TokenPresenter`: Formata tokens e informações relacionadas
- `ErrorPresenter`: Formata respostas de erro para APIs
- `ResponsePresenter`: Apresenta respostas padrão em formato consistente
- `PagePresenter`: Formata dados para renderização de templates HTML

## Princípios de Design

- Os presenters devem ser independentes das tecnologias de apresentação específicas
- Separar claramente a lógica de formatação da lógica de negócio
- Utilizar DTOs para transferir dados entre camadas
- Implementar transformações consistentes para cada tipo de dado
- Manter a lógica de apresentação fora dos casos de uso e entidades