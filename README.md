# Auth Service Go

Pequeno projeto educacional em Go para modelar claims de autenticação, gerar uma estrutura com identificador de usuário, papel e expiração, e verificar se a estrutura ainda está válida.

> **Importante:** a implementação atual não assina nem verifica JWT criptográfico e não expõe um servidor HTTP. Ela é um exercício de lógica de expiração, não deve ser usada como serviço de autenticação real.

## Tecnologias

- Go
- Biblioteca padrão
- Testes com `go test`

## Requisitos

Instale uma versão do Go compatível com o `go.mod`.

## Executar

```bash
go run .
```

## Testes

```bash
go test ./...
```

## Conceitos praticados

- Estruturas tipadas (`TokenClaim`)
- Validação de argumentos
- Expiração baseada em tempo
- Separação entre geração e validação
- Testes automatizados

## Limitações e próximos passos

- Implementar assinatura e verificação JWT com uma biblioteca mantida, incluindo validação de issuer, audience e algoritmo.
- Adicionar handlers HTTP e validação de entrada se a intenção for criar uma API.
- Validar papéis por allowlist e não confiar em papéis enviados pelo cliente.
- Adicionar testes para token expirado, usuário vazio e papel inválido.

Não utilize os claims atuais para proteger recursos reais.
