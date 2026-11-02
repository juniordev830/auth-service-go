# Auth Service Go

Biblioteca educacional em Go para emitir e verificar JWTs HS256 com foco em segurança, validação de claims e legibilidade do código.

## Visão geral

Este projeto demonstra:
- geração de tokens JWT assinados com HMAC-SHA256
- verificação de assinatura e claims
- validação de expiração e issuer/audience
- controle de papéis (`user` e `admin`)
- uso de segredo forte vindo de variável de ambiente

Ele foi pensado como base para autenticação em serviços backend, mas ainda não substitui um sistema completo de usuários, refresh tokens, persistência ou autenticação HTTP.

## Arquitetura

O código está organizado em blocos claros:
- `main.go`: geração, verificação e validação de tokens
- `README.md`: documentação do projeto
- `go.mod`: dependências do módulo
- `main_test.go`: testes de regressão e validação de regras

## Segurança

A biblioteca exige:
- segredo com pelo menos 32 bytes
- algoritmo `HS256`
- issuer e audience esperados
- `sub`, `role`, `exp`, `iat` validados
- rejeição de tokens malformados, expirados ou alterados
- limite de 256 bytes no identificador de usuário, também na validação de claims em memória

Importante:
- nunca versionar segredos no repositório
- nunca logar tokens em produção
- manter os secrets em gerenciador de segredos ou variáveis de ambiente

## Requisitos

- Go 1.22+
- Git

## Configuração

Se utilizar o helper em outra aplicação, defina a variável de ambiente no ambiente de execução (um arquivo `.env` não é carregado automaticamente por Go):

```bash
export JWT_SECRET="$(openssl rand -hex 32)"
```

## Executar

```bash
go test ./...
go run .
```

## Exemplo de uso

Exemplo ilustrativo de integração com o helper; substitua a função `main` demonstrativa existente caso o execute neste mesmo pacote. O programa atual em `main.go` apenas imprime uma mensagem.

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    secret := os.Getenv("JWT_SECRET")
    token, err := GenerateJWT("user-123", "user", secret)
    if err != nil {
        panic(err)
    }

    claims, err := VerifyJWT(token, secret)
    if err != nil {
        panic(err)
    }

    fmt.Println("user:", claims.UserID)
    fmt.Println("role:", claims.Role)
    fmt.Println("expiresAt:", claims.ExpiresAt)
}
```

## Fluxo de autenticação

1. o cliente envia credenciais para um endpoint de login
2. o backend valida a identidade do usuário
3. o backend gera um JWT com `sub`, `role`, `exp` e `iss`
4. o cliente envia o token em requisições subsequentes
5. o backend valida assinatura, expiração e claims

## Limitações

Este projeto ainda não implementa:
- login de usuários
- usuário em banco de dados
- refresh token
- persistência de sessões
- middleware HTTP real
- autorização por roles em endpoints

## Estrutura do projeto

O projeto atual inclui `main.go`, `main_test.go`, `go.mod`, `.gitignore`, `README.md`, `VSCODE_SETUP.md` e o workflow em `.github/workflows/ci.yml`. Não há servidor HTTP, Dockerfile ou `.env.example` nesta versão.

## CI/CD

O repositório já conta com uma pipeline de CI para validar:
- build
- testes
- verificação com `go vet`

## Autor

João Junior

GitHub: @juniordev830
