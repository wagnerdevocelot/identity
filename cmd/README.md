# Command Layer

## Responsabilidade

O diretório `cmd` contém os pontos de entrada da aplicação, como binários executáveis e serviços principais. Cada subdiretório tipicamente representa um executável diferente do projeto.

### Princípios

- Contém código mínimo, servindo principalmente como ponto de montagem
- Inicializa e configura a aplicação
- Conecta as diferentes camadas e componentes
- Inicia servidores, workers ou outros processos de longa duração

### Estrutura

- `/identity`: Aplicação principal do servidor de identidade

### Funções Principais

- Configuração inicial da aplicação
- Injeção de dependências
- Inicialização de servidores HTTP/gRPC
- Configuração de logging
- Tratamento de sinais do sistema operacional
- Gerenciamento do ciclo de vida da aplicação

O código neste diretório deve ser mantido o mais simples possível, delegando a maior parte da complexidade para as outras camadas da arquitetura.