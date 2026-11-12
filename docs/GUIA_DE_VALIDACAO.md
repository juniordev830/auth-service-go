# Guia de manutenção — Auth Service Go

## Escopo confirmado

Biblioteca educacional de JWT HS256, claims e autorização por função. Não equivale a uma solução completa de identidade.

## Arquivos principais

`main.go`, `authorization.go`, `middleware.go`, `http_authorization.go` e `*_test.go`.

## Validar uma alteração

No diretório raiz, usar os comandos adequados ao ambiente: `go test -race ./...` e `go vet ./...`.

Registrar o resultado dos testes no PR e conferir se a execução do GitHub Actions corresponde ao commit revisado. Não presumir que a interface ou o serviço é de produção apenas porque o build passou.

## Revisão de casos críticos

Testar algoritmo inválido, assinatura alterada, segredo fraco, clock skew, expiração, audience/issuer, papéis e múltiplos cabeçalhos Authorization.

## Limites e próxima entrega

Nunca inserir segredo real em exemplos. Para produção: rotação de chaves, refresh seguro, persistência de usuários e auditoria de autenticação.

### Checklist para PR

- [ ] A mudança está associada a um comportamento identificável.
- [ ] Foram documentados os casos novos e os limites encontrados.
- [ ] Há teste automatizado quando o módulo comporta execução reproduzível.
- [ ] Exemplos não contêm credenciais ou dados reais.
- [ ] A branch pode ser revisada antes de qualquer merge na principal.
