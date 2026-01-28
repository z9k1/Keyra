# Keyra

Backend de autenticação moderna com magic link, sessões seguras e rotação de refresh token.

## Stack
- FastAPI + Python
- PostgreSQL
- Redis
- SQLAlchemy 2.0 + Alembic
- Next.js 14 + TypeScript + Tailwind (frontend)

## Estrutura
```
Keyra/
  app/                # Backend FastAPI
  alembic/            # Migrations
  frontend/           # Frontend Next.js
```

## Requisitos
- Python 3.11+
- Node.js 18+
- Docker (recomendado para Postgres/Redis)

## Backend (FastAPI)

### 1) Subir Postgres e Redis
```bash
# Postgres
docker run -d --name keyra-postgres -e POSTGRES_DB=keyra -e POSTGRES_USER=keyra -e POSTGRES_PASSWORD=keyra -p 5432:5432 postgres:16

# Redis
docker run -d --name keyra-redis -p 6379:6379 redis:7
```

### 2) Configurar ambiente
```bash
cd D:\Keyra\Keyra
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
copy .env.example .env
```

Edite o `.env` e ajuste as variáveis necessárias (ex: `CORS_ALLOW_ORIGINS`, `FRONTEND_BASE_URL`).

### 3) Rodar migrations
```bash
alembic upgrade head
```

### 4) Iniciar API
```bash
uvicorn app.main:app --reload
```

- API: http://127.0.0.1:8000
- Docs: http://127.0.0.1:8000/docs

## Frontend (Next.js)

### 1) Instalar dependências
```bash
cd D:\Keyra\Keyra\frontend
npm install
copy .env.example .env
```

### 2) Rodar
```bash
npm run dev
```

- App: http://localhost:3000

## Fluxo de login (dev)
- `/login` → envia magic link
- O magic link é enviado por email via Resend se configurado.
- Em desenvolvimento, se não houver `RESEND_API_KEY`, o link é logado no terminal do backend.

## Variáveis importantes (.env)
Backend:
```
CORS_ALLOW_ORIGINS=http://localhost:3000
FRONTEND_BASE_URL=http://localhost:3000
RESEND_API_KEY=
EMAIL_FROM=
```

Frontend:
```
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

## Observações
- Tokens são salvos apenas como hash.
- Magic link expira rapidamente.
- Refresh token tem rotação e detecção de reuse.

---
Se precisar de ajustes ou deploy, me chama.
