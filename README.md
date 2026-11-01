# Auth Service Go

Biblioteca educacional em Go para emitir e verificar tokens JWT assinados com HMAC-SHA256 (HS256), além de validar claims em memória.

## Segurança

- `GenerateJWT` e `VerifyJWT` exigem um segredo com pelo menos 32 bytes.
- A verificação confere a assinatura em tempo constante, algoritmo, tipo, emissor, audiência, papel, usuário, horário de emissão e expiração.
- Os papéis permitidos são `user` e `admin`; não confie em papéis enviados diretamente pelo cliente.
- Forneça o segredo por variável de ambiente/gerenciador de segredos; nunca o versiona no repositório.
- O repositório ainda não fornece login, armazenamento de usuários, refresh tokens nem servidor HTTP. Não é um serviço de autenticação completo até esses componentes serem implementados.

## Executar

```bash
go test ./...
go run .
```

## Exemplo de uso como biblioteca

```go
secret := os.Getenv("JWT_SECRET")
token, err := GenerateJWT("user-123", "user", secret)
claims, err := VerifyJWT(token, secret)
```

O exemplo é ilustrativo; trate erros e não exponha tokens em logs.
