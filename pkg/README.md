# Package Layer

## Responsabilidade

O diretório `pkg` contém bibliotecas e componentes reutilizáveis que podem ser compartilhados externamente com outros projetos. É onde colocamos código que pode ser potencialmente publicado como bibliotecas independentes.

### Princípios

- Contém código de utilidade geral não específico do domínio
- Mantém dependências mínimas
- Fornece funcionalidade de uso comum
- Deve ser estável e bem testado
- Pode ser importado por outros projetos

### Exemplos de Componentes

- Utilitários de criptografia
- Parsers e formatadores
- Clientes HTTP configuráveis
- Middleware reutilizável
- Validadores comuns
- Helpers para logging e tracing

A principal diferença entre `pkg` e `internal` é que o código em `internal` não deve ser importado por outros projetos (e é protegido pelo compilador Go), enquanto o código em `pkg` é destinado a ser potencialmente compartilhado.