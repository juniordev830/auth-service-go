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
- validação estrita de `sub` e `role`: os claims verificados devem ter formato canônico, sem espaços extras nem papéis com maiúsculas; a validação em memória também rejeita expiração muito distante
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

## Validação de cabeçalho HTTP Bearer

O helper `VerifyAuthorizationHeader(valor, secret)` recebe **o valor de um único cabeçalho** `Authorization`, verifica o esquema `Bearer` (sem distinguir maiúsculas e minúsculas), rejeita espaços dentro do token e quebras de linha e, em seguida, chama `VerifyJWT` para validar a assinatura e as claims.

Exemplo em um handler já existente:

```go
claim, err := VerifyAuthorizationHeader(r.Header.Get("Authorization"), secret)
if err != nil {
    http.Error(w, "unauthorized", http.StatusUnauthorized)
    return
}
fmt.Println("authenticated user:", claim.UserID)
```

O exemplo acima pressupõe que `r`, `w` e `secret` já existam no handler; ele não constitui um servidor completo. **Antes de usar em produção, rejeite múltiplos cabeçalhos Authorization** com `len(r.Header.Values("Authorization")) != 1`, configure TLS e aplique autorização por recurso. Tokens não devem aparecer nos logs.

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


## Proteção HTTP com Bearer (novo)

Além das funções de emissão/verificação de JWT, o projeto agora oferece **`NewBearerMiddleware`** para proteger um `http.Handler`. A configuração valida um segredo mínimo de 32 bytes e permite limitar o acesso aos papéis canônicos `user` e `admin`. Sem papéis informados, ambos são aceitos após verificar assinatura e claims.

```go
guard, err := NewBearerMiddleware(os.Getenv("JWT_SECRET"), "admin")
if err != nil { log.Fatal(err) }

private := guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    claim, ok := VerifiedClaim(r.Context())
    if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
    fmt.Fprintln(w, "authenticated user:", claim.UserID)
}))
http.Handle("/admin", private)
```

**Comportamento de segurança:** cabeçalhos ausentes, repetidos ou malformados recebem HTTP **401** e desafio `WWW-Authenticate`; token válido sem papel permitido recebe **403**. Os tokens e segredos nunca são incluídos nas respostas. Os claims só são colocados no contexto após verificação de assinatura, expiração, emissor e audiência.

Essa biblioteca **não implementa** banco de usuários, revogação, rate limiting, TLS, proteção CSRF ou renovação de JWT. Para uma implantação real, usar HTTPS, gerenciamento de segredos, logs sem tokens e uma estratégia para revogar credenciais comprometidas. Execute `go test ./...` para validar os novos testes com `httptest`.

## Integração HTTP segura

Para validar requisições HTTP, use `VerifyAuthorizationRequest(request, secret)` em vez de extrair diretamente `request.Header.Get("Authorization")`. O helper exige **exatamente um** cabeçalho de autorização, rejeita valores duplicados (inclusive chaves com capitalização diferente em objetos `http.Header` criados manualmente) e reutiliza a verificação JWT existente. Não oferece autenticação de usuários nem autorização por recurso; é uma rotina de validação de token de acesso.

## Validação e manutenção

Consulte o [guia técnico de validação](docs/GUIA_DE_VALIDACAO.md) antes de alterar o código: ele reúne os comandos, casos de regressão e limites atuais do projeto.
