# CodeFlow Backend API

API REST em Flask + SQLite para o produto de autofix de código.

## Stack
- **Python 3.12** + **Flask 3.x**
- **SQLite** com WAL mode (zero config, swap por PostgreSQL em produção)
- **PyJWT** para autenticação
- Sem dependências pesadas — roda em qualquer lugar

## Instalação

```bash
cd backend
pip install flask pyjwt
python app.py
# API rodando em http://localhost:8000
```

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `PORT` | `8000` | Porta do servidor |
| `SECRET_KEY` | `codeflow-dev-...` | Chave JWT — **mude em produção** |
| `DATABASE` | `codeflow.db` | Caminho do SQLite |
| `CORS_ORIGINS` | `*` | Origens permitidas |

---

## Endpoints

### Auth

#### `POST /auth/register`
Cria uma conta nova.
```json
{ "email": "dev@startup.com", "name": "Ana Silva", "password": "senha123" }
```
Retorna `{ token, user }`.

#### `POST /auth/login`
Login com email + senha. Retorna `{ token, user }`.

#### `GET /auth/me`
🔒 Retorna dados do usuário autenticado.

---

### Repositórios

#### `GET /repos`
🔒 Lista repositórios conectados do usuário.

#### `POST /repos`
🔒 Conecta um novo repositório.
```json
{ "name": "api-core", "full_name": "startup/api-core", "language": "python", "framework": "fastapi" }
```
> Plano Starter: limite de 1 repo.

#### `DELETE /repos/:id`
🔒 Desconecta um repositório.

---

### Scans

#### `POST /repos/:id/scan`
🔒 Inicia análise do repositório. Retorna o scan com contagem de issues.

#### `GET /repos/:id/scans`
🔒 Histórico de scans do repositório.

---

### Issues

#### `GET /repos/:id/issues`
🔒 Lista issues do repositório.

Query params:
- `severity` — `high`, `medium`, `low`
- `status` — `open` (padrão), `fixed`, `ignored`
- `limit` — máximo 100

#### `GET /issues/:id`
🔒 Detalhe de um issue com o diff do fix.

#### `PATCH /issues/:id/status`
🔒 Atualiza status do issue.
```json
{ "status": "fixed" }  // open | fixed | ignored
```

#### `POST /issues/:id/fix`
🔒 Cria PR com o fix automático. Atualiza o issue para `fixed`.

---

### Pull Requests

#### `GET /repos/:id/pull-requests`
🔒 Lista PRs do repositório.

---

### Dashboard

#### `GET /dashboard`
🔒 Métricas consolidadas de todos os repos do usuário.
```json
{
  "metrics": { "open_issues": 8, "fixed_issues": 24, "open_prs": 3, "code_score": 74 },
  "top_rules": [...],
  "recent_issues": [...],
  "repos": [...]
}
```

---

### Time

#### `GET /team`
🔒 Lista membros do time.

#### `POST /team`
🔒 Adiciona membro (planos Team/Scale).
```json
{ "name": "Pedro Costa", "email": "pedro@startup.com", "role": "developer" }
```

---

### Billing

#### `POST /billing/upgrade`
🔒 Simula upgrade de plano.
```json
{ "plan": "team" }  // starter | team | scale
```

---

## Modelo de dados

```
users          → repos → scans → issues
                       → pull_requests
users          → team_members
```

## Migrando para produção

1. Troque SQLite por PostgreSQL (mudar a string de conexão + `psycopg2`)
2. Adicione Redis para queue de scans assíncronos
3. Use Gunicorn: `gunicorn app:app -w 4 -b 0.0.0.0:8000`
4. Configure `SECRET_KEY` e `CORS_ORIGINS` via env vars
5. Integre GitHub App real via OAuth + Webhooks no endpoint `/webhooks/github`
