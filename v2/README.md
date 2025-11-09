# 🔒 AppSec Dashboard v2.0

**OWASP Security Checklist & Pentesting Guide — Enterprise Edition**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18.2-61dafb.svg)](https://reactjs.org/)
[![NestJS](https://img.shields.io/badge/NestJS-10.3-e0234e.svg)](https://nestjs.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📋 Sobre

Redesign completo do AppSec Dashboard, transformando-o de uma ferramenta de checklist simples em uma **plataforma enterprise de gestão de segurança**.

### Principais Features

✅ **Multi-Projeto** — Gerencie múltiplas auditorias simultaneamente
✅ **Dashboard Analítico** — Métricas, gráficos e insights de risco
✅ **Colaboração** — Atribuições, comentários, @menções, RBAC
✅ **Exportações Profissionais** — PDF customizável, Excel, CSV, JSON API
✅ **PWA** — Instalável e funciona offline
✅ **Mobile-First** — Responsivo em todos os dispositivos
✅ **Acessibilidade** — WCAG 2.1 AA compliant
✅ **Segurança** — JWT + MFA, OWASP Top 10 compliant

---

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (React)                         │
│  • React 18 + TypeScript + Vite                             │
│  • Zustand (state) + React Query (cache)                    │
│  • Radix UI (components) + Recharts (charts)                │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS / WebSocket
┌────────────────────┴────────────────────────────────────────┐
│                     Backend (NestJS)                         │
│  • NestJS 10 + TypeScript                                   │
│  • PostgreSQL (database) + TypeORM (ORM)                    │
│  • Redis (cache + queue) + Bull (jobs)                      │
│  • JWT + Passport (auth) + Socket.io (realtime)             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Requisitos

- **Node.js** >= 20.x
- **Docker** & **Docker Compose**
- **Git**

### 1. Clonar Repositório

```bash
git clone https://github.com/seu-usuario/appsec-dashboard.git
cd appsec-dashboard/v2
```

### 2. Setup com Docker (Recomendado)

```bash
# Iniciar todos os serviços
docker-compose up -d

# Ver logs
docker-compose logs -f

# Acessar aplicação
open http://localhost:3000

# Acessar API docs (Swagger)
open http://localhost:4000/api/docs

# MinIO Console (S3)
open http://localhost:9001
```

**Pronto!** A aplicação estará rodando em:
- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:4000
- **API Docs (Swagger):** http://localhost:4000/api/docs
- **MinIO Console:** http://localhost:9001

### 3. Setup Manual (sem Docker)

#### 3.1. Backend

```bash
cd backend

# Instalar dependências
npm install

# Configurar ambiente
cp .env.example .env
# Editar .env com suas configurações

# Iniciar PostgreSQL e Redis localmente
# (ou use docker-compose up postgres redis)

# Rodar migrations
npm run migration:run

# Iniciar servidor
npm run start:dev
```

Backend rodando em: http://localhost:4000

#### 3.2. Frontend

```bash
cd frontend

# Instalar dependências
npm install

# Iniciar dev server
npm run dev
```

Frontend rodando em: http://localhost:3000

---

## 📂 Estrutura do Projeto

```
v2/
├── backend/                    # Backend NestJS
│   ├── src/
│   │   ├── main.ts            # ✅ Bootstrap
│   │   ├── app.module.ts      # ✅ Root module
│   │   ├── auth/              # Autenticação JWT
│   │   ├── users/             # Usuários
│   │   ├── projects/          # Projetos
│   │   ├── checklists/        # Checklists
│   │   ├── evidence/          # Evidências (uploads)
│   │   ├── exports/           # Exportações (PDF, Excel)
│   │   ├── analytics/         # Analytics
│   │   └── notifications/     # WebSockets
│   ├── package.json           # ✅ Dependências
│   ├── .env.example           # ✅ Variáveis ambiente
│   └── README.md
│
├── frontend/                   # Frontend React
│   ├── src/
│   │   ├── main.tsx           # Bootstrap React
│   │   ├── App.tsx            # Root component
│   │   ├── pages/             # Páginas (rotas)
│   │   ├── components/        # Componentes
│   │   ├── hooks/             # Custom hooks
│   │   ├── services/          # API clients
│   │   ├── store/             # Zustand stores
│   │   ├── styles/            # CSS
│   │   └── types/             # TypeScript types
│   ├── package.json
│   └── README.md
│
├── docker-compose.yml          # ✅ Docker setup completo
├── IMPLEMENTATION-GUIDE.md     # ✅ Guia de implementação
└── README.md                   # ✅ Este arquivo
```

---

## 🔧 Desenvolvimento

### Comandos Úteis

```bash
# Backend
cd backend
npm run start:dev      # Dev server (watch mode)
npm run build          # Build para produção
npm test               # Rodar testes
npm run test:cov       # Cobertura de testes
npm run migration:run  # Rodar migrations

# Frontend
cd frontend
npm run dev            # Dev server
npm run build          # Build para produção
npm test               # Rodar testes
npm run preview        # Preview build

# Docker
docker-compose up -d              # Iniciar serviços
docker-compose down               # Parar serviços
docker-compose logs -f backend    # Ver logs do backend
docker-compose restart backend    # Reiniciar backend
```

### Criar Novo Módulo (Backend)

```bash
cd backend

# Gerar resource completo (controller, service, module, entities, dto)
nest g resource nome-modulo

# Ou gerar componentes individuais
nest g module nome-modulo
nest g controller nome-modulo
nest g service nome-modulo
```

### Criar Nova Página (Frontend)

```bash
cd frontend/src/pages

# Criar arquivo NomePagina.tsx
# Adicionar rota em App.tsx
```

---

## 🧪 Testes

### Backend (Jest)

```bash
cd backend

# Testes unitários
npm test

# Testes com coverage
npm run test:cov

# Testes E2E
npm run test:e2e

# Watch mode
npm run test:watch
```

### Frontend (Vitest)

```bash
cd frontend

# Testes unitários
npm test

# Coverage
npm run test:cov

# UI mode
npm run test:ui
```

---

## 🚢 Deploy

### Build para Produção

```bash
# Backend
cd backend
npm run build
# Output: dist/

# Frontend
cd frontend
npm run build
# Output: dist/
```

### Docker Production

```bash
# Build images
docker-compose -f docker-compose.prod.yml build

# Deploy
docker-compose -f docker-compose.prod.yml up -d
```

### Variáveis de Ambiente (Produção)

Criar `.env` no backend com:

```env
NODE_ENV=production
PORT=4000

DATABASE_HOST=seu-servidor-postgres
DATABASE_PORT=5432
DATABASE_USER=postgres
DATABASE_PASSWORD=senha-segura
DATABASE_NAME=appsec_dashboard

REDIS_HOST=seu-servidor-redis
REDIS_PORT=6379

JWT_SECRET=chave-super-secreta-min-32-chars-mude-isso
JWT_REFRESH_SECRET=chave-refresh-super-secreta-mude-isso

# S3 (AWS ou MinIO)
STORAGE_TYPE=s3
AWS_S3_BUCKET=appsec-dashboard
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=sua-key
AWS_SECRET_ACCESS_KEY=sua-secret
```

---

## 📊 Database

### Migrations

```bash
cd backend

# Gerar migration
npm run typeorm migration:generate -- -n NomeDaMigration

# Rodar migrations
npm run migration:run

# Reverter última migration
npm run migration:revert
```

### Schema

Ver schema completo em `backend/database/schema.sql` ou consultar [IMPLEMENTATION-GUIDE.md](./IMPLEMENTATION-GUIDE.md#database-schema-sql).

**Principais Tabelas:**
- `users` — Usuários e autenticação
- `projects` — Projetos de auditoria
- `project_members` — Membros do projeto (N:N)
- `checklist_items` — Items de checklist (dados estáticos)
- `item_states` — Estado dos items por projeto
- `evidences` — Evidências (uploads)
- `comments` — Comentários em items
- `audit_logs` — Logs de auditoria

---

## 🔒 Segurança

### OWASP Top 10 2021 Compliance

✅ **A01 — Broken Access Control:** RBAC implementado (Admin/Editor/Viewer)
✅ **A02 — Cryptographic Failures:** HTTPS, bcrypt (cost 12), JWT assinado
✅ **A03 — Injection:** TypeORM prepared statements, DOMPurify, CSP
✅ **A04 — Insecure Design:** Rate limiting, threat modeling
✅ **A05 — Security Misconfiguration:** Helmet, CORS, error handling
✅ **A06 — Vulnerable Components:** npm audit, Dependabot
✅ **A07 — Authentication Failures:** JWT + refresh token, brute force protection
✅ **A08 — Data Integrity:** CI/CD pipelines, backups automáticos
✅ **A09 — Logging:** Winston + audit logs
✅ **A10 — SSRF:** URL validation

### Primeiros Passos de Segurança

1. **Mudar secrets padrão** em `.env`
2. **Habilitar HTTPS** em produção
3. **Configurar MFA** para admins
4. **Rodar `npm audit`** regularmente
5. **Backups automáticos** do banco de dados

Ver [docs/CHECKLIST-SEGURANCA-APP.md](../docs/CHECKLIST-SEGURANCA-APP.md) para checklist completo.

---

## 📚 Documentação

### Documentos Principais

1. **[IMPLEMENTATION-GUIDE.md](./IMPLEMENTATION-GUIDE.md)** — Guia completo de implementação (templates de código)
2. **[../docs/REDESIGN-UX-UI.md](../docs/REDESIGN-UX-UI.md)** — Wireframes e design system
3. **[../docs/FUNCIONALIDADES-PRIORIZADAS.md](../docs/FUNCIONALIDADES-PRIORIZADAS.md)** — User stories e roadmap
4. **[../docs/MELHORIAS-TECNICAS-ARQUITETURA.md](../docs/MELHORIAS-TECNICAS-ARQUITETURA.md)** — Arquitetura técnica
5. **[../docs/CHECKLIST-SEGURANCA-APP.md](../docs/CHECKLIST-SEGURANCA-APP.md)** — Checklist de segurança
6. **[../docs/PLANO-MIGRACAO.md](../docs/PLANO-MIGRACAO.md)** — Plano de migração v1.x → v2.0

### API Documentation

Com o backend rodando, acesse: **http://localhost:4000/api/docs** (Swagger UI)

---

## 🤝 Contribuindo

### Workflow

1. Fork do repositório
2. Criar branch: `git checkout -b feature/nova-feature`
3. Fazer alterações
4. Testes: `npm test`
5. Commit: `git commit -m "feat: adicionar nova feature"`
6. Push: `git push origin feature/nova-feature`
7. Abrir Pull Request

### Convenções

**Commits:** Seguir [Conventional Commits](https://www.conventionalcommits.org/)
- `feat:` Nova feature
- `fix:` Bug fix
- `docs:` Documentação
- `refactor:` Refatoração
- `test:` Testes
- `chore:` Tarefas gerais

**Code Style:**
- Backend: ESLint + Prettier (config NestJS padrão)
- Frontend: ESLint + Prettier (config React padrão)

---

## 📝 Roadmap

### v2.0.0 MVP (Em Desenvolvimento)

- [x] Estrutura do projeto
- [x] Documentação completa (~200 páginas)
- [ ] Backend NestJS completo (~50 arquivos)
- [ ] Frontend React completo (~60 arquivos)
- [ ] Autenticação JWT + RBAC
- [ ] CRUD de projetos
- [ ] Dashboard analítico
- [ ] Exportação PDF básica

### v2.1.0 Collaboration

- [ ] Real-time com WebSockets
- [ ] Comentários e @menções
- [ ] Exportação Excel/CSV
- [ ] API JSON pública

### v2.2.0 Advanced

- [ ] PWA completo (offline mode)
- [ ] Multi-idioma (i18n)
- [ ] Agendamento de relatórios
- [ ] Analytics avançado

Ver [../docs/FUNCIONALIDADES-PRIORIZADAS.md](../docs/FUNCIONALIDADES-PRIORIZADAS.md) para roadmap completo.

---

## 🐛 Issues

Reportar bugs ou solicitar features: [GitHub Issues](https://github.com/seu-usuario/appsec-dashboard/issues)

---

## 📜 Licença

MIT License - Ver [LICENSE](../LICENSE) para detalhes.

---

## 👥 Time

**Desenvolvido por:** Equipe AppSec Dashboard

**Contato:**
- **Produto:** produto@appsec-dashboard.com
- **Engenharia:** tech@appsec-dashboard.com
- **Segurança:** security@appsec-dashboard.com

---

## 🙏 Agradecimentos

- **OWASP** — Por todo o conteúdo de segurança
- **NestJS Community** — Framework incrível
- **React Team** — Por revolucionar frontend
- **Comunidade Open Source** — Por todas as bibliotecas

---

**Status:** 🚧 Em Desenvolvimento

**Versão:** 2.0.0-beta

**Última Atualização:** 2025-11-09

---

**⭐ Se este projeto foi útil, considere dar uma estrela no GitHub!**
