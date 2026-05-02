# tplink-deco-api

SDK Python para acesso e controle de roteadores **TP-Link Deco** (mesh Wi-Fi) via API HTTP interna. A API do Deco usa autenticação proprietária com RSA/AES. O objetivo é permitir automação programática sem depender do app oficial.

## Instruções de commit

Sempre use commits semânticos em **português do Brasil**.

### Formato

```
<tipo>(<escopo opcional>): <descrição curta>

<resumo obrigatório das alterações>

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
```

### Tipos permitidos

| Tipo | Uso |
|------|-----|
| `feat` | Nova funcionalidade |
| `fix` | Correção de bug |
| `refactor` | Refatoração sem mudança de comportamento |
| `test` | Adição ou correção de testes |
| `docs` | Documentação |
| `chore` | Tarefas de manutenção, dependências, configuração |
| `style` | Formatação, lint (sem mudança de lógica) |
| `perf` | Melhoria de performance |
| `ci` | Mudanças em pipelines de CI/CD |

### Regras

- A descrição curta deve estar em letras minúsculas e sem ponto final
- O resumo deve explicar **o que** foi alterado e **por quê**, em português do Brasil
- Use o corpo do commit para listar os arquivos ou módulos afetados quando relevante
- Prefira commits atômicos: um assunto por commit

### Exemplos

```
feat(auth): adiciona autenticação por token na API Deco

Implementa o fluxo de login com geração e validação de token AES.
Afeta: tplink_deco_api/auth.py, tplink_deco_api/client.py
```

```
fix(client): corrige timeout em requisições longas

O cliente HTTP não respeitava o parâmetro de timeout configurado.
Afeta: tplink_deco_api/client.py
```

```
chore: atualiza dependências do projeto

Atualiza versões no pyproject.toml para compatibilidade com Python 3.14.
```