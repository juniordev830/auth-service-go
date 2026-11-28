# Engenharia reversa e estudo — Auth Service Go

## Objetivo e fluxo

Emissão e verificação de JWT HS256 para estudo. main.go implementa a emissão e a validação. authorization.go interpreta o cabeçalho HTTP e middleware.go disponibiliza o resultado verificado ao handler.

**Tecnologias identificadas** · Go.

**Revisão de referência** · `8acafda942be`.

## Mapa do código

| Caminho | Papel de leitura | Símbolos selecionados |
| --- | --- | --- |
| [authorization.go](../authorization.go) | Implementação | `VerifyAuthorizationHeader` |
| [http_authorization.go](../http_authorization.go) | Implementação | `VerifyAuthorizationRequest` |
| [main.go](../main.go) | Ponto de leitura para entrada ou composição | `validateSecret`, `GenerateToken`, `TokenFingerprint`, `GenerateJWT`, `VerifyJWT`, `ValidateToken`, `main` |
| [middleware.go](../middleware.go) | Implementação | `VerifiedClaim`, `NewBearerMiddleware`, `writeUnauthorized` |

## Configuração e referências

Ambiente e dependências: [go.mod](../go.mod).

Referências existentes: [docs/GUIA_DE_VALIDACAO.md](GUIA_DE_VALIDACAO.md).

## Roteiro de estudo e desenvolvimento

1. Comece pelo fluxo descrito acima e localize seus pontos de entrada no mapa. Acompanhe uma entrada válida até a transformação ou a resposta.
2. Abra um teste relacionado ao fluxo e descreva qual regra ele protege. Compare o tratamento esperado para entradas válidas, inválidas e nos limites.
3. Ao adicionar uma regra, determine qual módulo controla o dado e cubra o caso nesse nível. Em seguida, confira o efeito no comando, na API ou na interface de entrada.

**Pergunta de entrevista**

Por que o código de negócio deve consumir as claims verificadas, após a validação do token?

## Testes versionados

Arquivos para começar a leitura dos cenários de teste: [authorization_test.go](../authorization_test.go), [http_authorization_test.go](../http_authorization_test.go), [main_test.go](../main_test.go), [middleware_test.go](../middleware_test.go).

Os comandos e versões de runtime usados no CI ficam em [.github/workflows/ci.yml](../.github/workflows/ci.yml), [.github/workflows/seguranca-workflows.yml](../.github/workflows/seguranca-workflows.yml).

[Voltar ao README](../README.md).
