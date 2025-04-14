# Interface Layer

## Responsabilidade

O diretório `interface` contém os adaptadores que permitem a comunicação entre o sistema e agentes externos (usuários, outros sistemas, etc.). Esta camada é responsável por converter dados entre o formato mais conveniente para entidades externas e o formato mais conveniente para os casos de uso internos.

### Princípios

- Depende das camadas de domínio e usecase
- Implementa adaptadores para interfaces externas (HTTP, CLI, etc.)
- Converte dados entre formatos externos e internos
- Não contém lógica de negócio ou aplicação

### Estrutura

- `/http`: Controladores e handlers HTTP para API REST/JSON
- `/api`: Definições de API e documentação (Swagger/OpenAPI)
- `/presenter`: Transformadores de dados que preparam as respostas para diferentes formatos

### Exemplos de Controladores

- AuthController
- TokenController
- UserController
- ConsentController

Esta camada pode ser modificada para acomodar novos métodos de entrada/saída ou formatos de dados sem necessariamente afetar a lógica do negócio ou dos casos de uso.