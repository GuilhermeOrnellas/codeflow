# 🌊 CodeFlow

Autofix inteligente para times de dev. Detecta, explica e corrige bugs automaticamente.

## Estrutura

```
codeflow/
├── frontend/
│   └── index.html      ← Abra direto no browser (landing + onboarding + dashboard)
├── backend/
│   ├── app.py          ← API Flask + SQLite
│   └── README.md       ← Documentação completa dos endpoints
├── start.sh            ← Inicia o backend
└── README.md
```

## Como rodar

### Backend (API)
```bash
pip install flask pyjwt
./start.sh
# API disponível em http://localhost:8000
```

### Frontend
Abra `frontend/index.html` direto no navegador.
A barra inferior mostra se o backend está conectado.

## O que está incluso

- **Landing page** completa com hero, code preview, steps, depoimentos e pricing
- **Onboarding** de 4 passos: cadastro → repo → scan → resultados
- **Dashboard** com métricas, lista de issues, gráficos e modal de fix/PR
- **API REST** com 14 endpoints: auth, repos, scans, issues, PRs, team, billing
- **Autenticação JWT** + persistência de sessão
- **Motor de análise** simulado com regras reais de Python, JS e TypeScript

## Endpoints principais

| Método | Rota | Descrição |
|--------|------|-----------|
| POST | /auth/register | Criar conta |
| POST | /auth/login | Login |
| GET | /auth/me | Usuário atual |
| POST | /repos | Conectar repositório |
| POST | /repos/:id/scan | Iniciar análise |
| GET | /repos/:id/issues | Listar issues |
| POST | /issues/:id/fix | Criar PR com fix |
| GET | /dashboard | Métricas do time |
| POST | /billing/upgrade | Mudar plano |

## Próximos passos para produção

1. Trocar SQLite → PostgreSQL
2. Integrar GitHub App OAuth real
3. Webhook `/webhooks/github` para scan em cada push
4. Queue assíncrona (Celery + Redis) para scans longos
5. Deploy: Gunicorn + Nginx ou Railway/Render
