# 🏗️ Melhorias Técnicas & Arquitetura — AppSec Dashboard v2.0

**Versão:** 2.0.0
**Data:** 2025-11-09
**Autor:** Time de Engenharia

---

## 📋 Índice

1. [Stack Tecnológico Proposto](#stack-tecnológico-proposto)
2. [Arquitetura de Sistema](#arquitetura-de-sistema)
3. [Design de APIs](#design-de-apis)
4. [Banco de Dados](#banco-de-dados)
5. [Serviço de Exportação](#serviço-de-exportação)
6. [Infraestrutura & DevOps](#infraestrutura--devops)
7. [Performance & Escalabilidade](#performance--escalabilidade)
8. [Comparação: Antes vs Depois](#comparação-antes-vs-depois)

---

## 💻 Stack Tecnológico Proposto

### Frontend

#### Migração: Vanilla JS → React + TypeScript

**Justificativa:**
- ✅ **Componentização:** Reutilização de código (cards, badges, modais)
- ✅ **Type Safety:** TypeScript previne bugs em runtime
- ✅ **Ecossistema:** Bibliotecas maduras (React Query, Zustand, React Router)
- ✅ **DevEx:** Hot reload, debugging, testing com Jest/Vitest
- ✅ **Escalabilidade:** Fácil adicionar novas features sem quebrar existentes

**Alternativas Consideradas:**
| Framework | Prós | Contras | Decisão |
|-----------|------|---------|---------|
| **React** | Ecossistema gigante, fácil contratar devs | Bundle size | ✅ **Escolhido** |
| **Vue 3** | Mais leve, sintaxe simples | Menor comunidade | ❌ |
| **Svelte** | Sem virtual DOM, muito performático | Ecossistema menor | ❌ |
| **Vanilla JS** | Zero deps, máxima performance | Difícil manter em escala | ❌ |

#### Stack Frontend Completo

```javascript
{
  "dependencies": {
    // Core
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "typescript": "^5.3.0",

    // Routing
    "react-router-dom": "^6.20.0",

    // State Management
    "zustand": "^4.4.7",              // Global state (simples e performático)
    "react-query": "^5.12.0",         // Server state (cache, refetch)

    // Forms & Validation
    "react-hook-form": "^7.49.0",
    "zod": "^3.22.4",                 // Schema validation

    // UI Components
    "@radix-ui/react-dialog": "^1.0.5",      // Modais acessíveis
    "@radix-ui/react-dropdown-menu": "^2.0.6",
    "@radix-ui/react-tabs": "^1.0.4",
    "@radix-ui/react-toast": "^1.1.5",

    // Data Visualization
    "recharts": "^2.10.0",            // Gráficos (radar, donut, bars)

    // Utilities
    "date-fns": "^3.0.0",             // Manipulação de datas
    "clsx": "^2.0.0",                 // Conditional classnames
    "dompurify": "^3.0.6",            // Sanitização XSS

    // Markdown
    "react-markdown": "^9.0.1",
    "remark-gfm": "^4.0.0",           // GitHub Flavored Markdown

    // i18n
    "react-i18next": "^13.5.0",
    "i18next": "^23.7.0",

    // PWA
    "workbox-webpack-plugin": "^7.0.0"
  },
  "devDependencies": {
    // Build Tools
    "vite": "^5.0.8",                 // Build tool (mais rápido que webpack)
    "@vitejs/plugin-react": "^4.2.1",

    // Testing
    "vitest": "^1.0.4",
    "@testing-library/react": "^14.1.2",
    "@testing-library/jest-dom": "^6.1.5",
    "playwright": "^1.40.0",          // E2E testing

    // Code Quality
    "eslint": "^8.56.0",
    "prettier": "^3.1.1",
    "typescript-eslint": "^6.15.0",

    // Types
    "@types/react": "^18.2.45",
    "@types/dompurify": "^3.0.5"
  }
}
```

**Vite Config (`vite.config.ts`):**

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/api\.appsec-dashboard\.com\/api\/v2\/.*/,
            handler: 'NetworkFirst',
            options: {
              cacheName: 'api-cache',
              expiration: {
                maxEntries: 50,
                maxAgeSeconds: 300 // 5 minutos
              }
            }
          }
        ]
      },
      manifest: {
        name: 'AppSec Dashboard',
        short_name: 'AppSec',
        description: 'OWASP Checklist & Pentesting Guide',
        theme_color: '#0e1f2f',
        icons: [
          {
            src: '/icon-192.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: '/icon-512.png',
            sizes: '512x512',
            type: 'image/png',
            purpose: 'any maskable'
          }
        ]
      }
    })
  ],
  build: {
    target: 'esnext',
    minify: 'terser',
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'ui-vendor': ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
          'charts': ['recharts']
        }
      }
    }
  },
  optimizeDeps: {
    include: ['react', 'react-dom']
  }
});
```

---

### Backend

#### Migração: Express.js + lowdb → NestJS + PostgreSQL

**Justificativa:**
- ✅ **TypeScript Nativo:** Type safety no backend
- ✅ **Modularidade:** Arquitetura baseada em modules, controllers, services
- ✅ **Dependency Injection:** Fácil testar e mockar serviços
- ✅ **Validação Automática:** Pipes do NestJS com class-validator
- ✅ **OpenAPI Built-in:** Documentação Swagger automática
- ✅ **Escalável:** WebSockets, microservices, GraphQL (se necessário)

**Alternativas Consideradas:**
| Framework | Prós | Contras | Decisão |
|-----------|------|---------|---------|
| **NestJS** | Arquitetura enterprise, TypeScript, DI | Curva de aprendizado | ✅ **Escolhido** |
| **Fastify** | Muito rápido, plugins | Menos estruturado | ❌ |
| **Express** | Simples, conhecimento existente | Não escala bem | ❌ (atual) |
| **tRPC** | Type-safe end-to-end | Requer full TypeScript stack | ❌ |

#### Stack Backend Completo

```json
{
  "dependencies": {
    // Framework
    "@nestjs/core": "^10.3.0",
    "@nestjs/common": "^10.3.0",
    "@nestjs/platform-express": "^10.3.0",

    // Database
    "@nestjs/typeorm": "^10.0.1",
    "typeorm": "^0.3.19",
    "pg": "^8.11.3",                  // PostgreSQL driver

    // Auth
    "@nestjs/jwt": "^10.2.0",
    "@nestjs/passport": "^10.0.3",
    "passport": "^0.7.0",
    "passport-jwt": "^4.0.1",
    "bcrypt": "^5.1.1",

    // Validation
    "class-validator": "^0.14.0",
    "class-transformer": "^0.5.1",

    // Config
    "@nestjs/config": "^3.1.1",
    "dotenv": "^16.3.1",

    // WebSockets
    "@nestjs/websockets": "^10.3.0",
    "@nestjs/platform-socket.io": "^10.3.0",

    // File Upload
    "multer": "^2.0.0-rc.4",
    "@nestjs/platform-express": "^10.3.0",

    // PDF Generation
    "puppeteer": "^21.6.1",
    "pdfkit": "^0.14.0",

    // Excel Export
    "exceljs": "^4.4.0",

    // Job Scheduling
    "@nestjs/schedule": "^4.0.0",
    "node-cron": "^3.0.3",

    // Rate Limiting
    "@nestjs/throttler": "^5.1.1",

    // Logging
    "winston": "^3.11.0",
    "@nestjs/winston": "^1.9.4",

    // Security
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.1.5",
    "express-mongo-sanitize": "^2.2.0",

    // Utilities
    "uuid": "^9.0.1",
    "date-fns": "^3.0.0"
  },
  "devDependencies": {
    "@nestjs/cli": "^10.2.1",
    "@nestjs/schematics": "^10.0.3",
    "@nestjs/testing": "^10.3.0",
    "@types/express": "^4.17.21",
    "@types/multer": "^1.4.11",
    "@types/bcrypt": "^5.0.2",
    "@types/passport-jwt": "^4.0.0",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "ts-jest": "^29.1.1",
    "ts-node": "^10.9.2"
  }
}
```

**NestJS Module Structure:**

```
src/
├── main.ts                          # Bootstrap da aplicação
├── app.module.ts                    # Root module
│
├── config/                          # Configurações
│   ├── database.config.ts
│   ├── jwt.config.ts
│   └── app.config.ts
│
├── auth/                            # Módulo de autenticação
│   ├── auth.module.ts
│   ├── auth.controller.ts
│   ├── auth.service.ts
│   ├── strategies/
│   │   ├── jwt.strategy.ts
│   │   └── local.strategy.ts
│   ├── guards/
│   │   ├── jwt-auth.guard.ts
│   │   └── roles.guard.ts
│   └── dto/
│       ├── login.dto.ts
│       └── register.dto.ts
│
├── users/                           # Módulo de usuários
│   ├── users.module.ts
│   ├── users.controller.ts
│   ├── users.service.ts
│   ├── entities/
│   │   └── user.entity.ts
│   └── dto/
│       ├── create-user.dto.ts
│       └── update-user.dto.ts
│
├── projects/                        # Módulo de projetos
│   ├── projects.module.ts
│   ├── projects.controller.ts
│   ├── projects.service.ts
│   ├── entities/
│   │   ├── project.entity.ts
│   │   ├── project-member.entity.ts
│   │   └── project-settings.entity.ts
│   └── dto/
│       ├── create-project.dto.ts
│       ├── update-project.dto.ts
│       └── filter-project.dto.ts
│
├── checklists/                      # Módulo de checklists
│   ├── checklists.module.ts
│   ├── checklists.controller.ts
│   ├── checklists.service.ts
│   ├── entities/
│   │   ├── checklist-item.entity.ts
│   │   ├── checklist-category.entity.ts
│   │   └── item-state.entity.ts
│   └── dto/
│       ├── update-item-state.dto.ts
│       └── filter-items.dto.ts
│
├── evidence/                        # Módulo de evidências
│   ├── evidence.module.ts
│   ├── evidence.controller.ts
│   ├── evidence.service.ts
│   ├── entities/
│   │   └── evidence.entity.ts
│   └── storage/
│       └── local-storage.service.ts
│
├── exports/                         # Módulo de exportações
│   ├── exports.module.ts
│   ├── exports.controller.ts
│   ├── exports.service.ts
│   ├── generators/
│   │   ├── pdf.generator.ts
│   │   ├── excel.generator.ts
│   │   └── csv.generator.ts
│   └── templates/
│       ├── executive.template.ts
│       └── technical.template.ts
│
├── notifications/                   # Módulo de notificações
│   ├── notifications.module.ts
│   ├── notifications.gateway.ts     # WebSocket
│   ├── notifications.service.ts
│   └── dto/
│       └── notification.dto.ts
│
├── analytics/                       # Módulo de analytics
│   ├── analytics.module.ts
│   ├── analytics.controller.ts
│   ├── analytics.service.ts
│   └── dto/
│       └── metrics.dto.ts
│
└── common/                          # Código compartilhado
    ├── decorators/
    │   ├── roles.decorator.ts
    │   └── current-user.decorator.ts
    ├── filters/
    │   └── http-exception.filter.ts
    ├── interceptors/
    │   ├── logging.interceptor.ts
    │   └── transform.interceptor.ts
    ├── pipes/
    │   └── validation.pipe.ts
    └── constants/
        ├── roles.enum.ts
        └── status.enum.ts
```

**Exemplo de Controller (TypeScript):**

```typescript
// src/projects/projects.controller.ts

import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  HttpCode,
  HttpStatus
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../common/decorators/roles.decorator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { ProjectsService } from './projects.service';
import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { FilterProjectDto } from './dto/filter-project.dto';
import { Role } from '../common/constants/roles.enum';

@ApiTags('projects')
@ApiBearerAuth()
@Controller('api/v2/projects')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ProjectsController {
  constructor(private readonly projectsService: ProjectsService) {}

  @Post()
  @Roles(Role.ADMIN, Role.EDITOR)
  @ApiOperation({ summary: 'Criar novo projeto' })
  @ApiResponse({ status: 201, description: 'Projeto criado com sucesso' })
  @ApiResponse({ status: 400, description: 'Dados inválidos' })
  @ApiResponse({ status: 401, description: 'Não autenticado' })
  @ApiResponse({ status: 403, description: 'Sem permissão' })
  async create(
    @CurrentUser('id') userId: string,
    @Body() createProjectDto: CreateProjectDto
  ) {
    return this.projectsService.create(userId, createProjectDto);
  }

  @Get()
  @ApiOperation({ summary: 'Listar projetos do usuário' })
  async findAll(
    @CurrentUser('id') userId: string,
    @Query() filterDto: FilterProjectDto
  ) {
    return this.projectsService.findAll(userId, filterDto);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Buscar projeto por ID' })
  async findOne(
    @CurrentUser('id') userId: string,
    @Param('id') projectId: string
  ) {
    return this.projectsService.findOne(userId, projectId);
  }

  @Patch(':id')
  @Roles(Role.ADMIN, Role.EDITOR)
  @ApiOperation({ summary: 'Atualizar projeto' })
  async update(
    @CurrentUser('id') userId: string,
    @Param('id') projectId: string,
    @Body() updateProjectDto: UpdateProjectDto
  ) {
    return this.projectsService.update(userId, projectId, updateProjectDto);
  }

  @Delete(':id')
  @Roles(Role.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Deletar projeto (apenas admin)' })
  async remove(
    @CurrentUser('id') userId: string,
    @Param('id') projectId: string
  ) {
    await this.projectsService.remove(userId, projectId);
  }

  @Patch(':id/archive')
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Arquivar projeto' })
  async archive(
    @CurrentUser('id') userId: string,
    @Param('id') projectId: string
  ) {
    return this.projectsService.archive(userId, projectId);
  }
}
```

**DTO com Validação:**

```typescript
// src/projects/dto/create-project.dto.ts

import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsArray,
  IsEnum,
  MinLength,
  MaxLength,
  ArrayMinSize
} from 'class-validator';

export class CreateProjectDto {
  @ApiProperty({ example: 'API de Pagamentos v2.1' })
  @IsString()
  @MinLength(3)
  @MaxLength(100)
  name: string;

  @ApiProperty({ example: 'Teste de segurança pré-produção', required: false })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;

  @ApiProperty({ example: ['user-123', 'user-456'] })
  @IsArray()
  @ArrayMinSize(1)
  @IsString({ each: true })
  teamMembers: string[];

  @ApiProperty({ example: ['owasp-web', 'api-security'] })
  @IsArray()
  @ArrayMinSize(1)
  @IsString({ each: true })
  categories: string[];

  @ApiProperty({ example: { client: 'Empresa X', deadline: '2025-12-31' }, required: false })
  @IsOptional()
  metadata?: Record<string, any>;
}
```

---

## 🏛️ Arquitetura de Sistema

### Arquitetura Atual (Monolítico Simples)

```
┌─────────────────────────────────────────┐
│         CLIENTE (Browser)               │
│    HTML + CSS + Vanilla JS              │
└─────────────────┬───────────────────────┘
                  │ HTTP
                  ▼
┌─────────────────────────────────────────┐
│      SERVIDOR (Node.js + Express)       │
│  ┌─────────────────────────────────┐   │
│  │  app.mjs (Frontend Logic)       │   │
│  │  server.mjs (Backend API)       │   │
│  │  data.mjs (Checklist Data)      │   │
│  └─────────────────────────────────┘   │
│              │                          │
│              ▼                          │
│  ┌─────────────────────────────────┐   │
│  │  lowdb (JSON File)              │   │
│  │  state.json                     │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

**Problemas:**
- ❌ **Acoplamento:** Frontend e backend no mesmo repositório/processo
- ❌ **Escalabilidade:** Não pode escalar horizontalmente (state.json único)
- ❌ **Confiabilidade:** Single point of failure
- ❌ **Performance:** Sem cache, sem CDN
- ❌ **Segurança:** Sem separação de concerns

---

### Arquitetura Proposta (3-Tier + Microsserviços Opcionais)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CAMADA 1: CLIENTE                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  React SPA (TypeScript)                                     │   │
│  │  ├── Components (UI)                                        │   │
│  │  ├── Pages (Routes)                                         │   │
│  │  ├── Zustand (State)                                        │   │
│  │  ├── React Query (Server Cache)                            │   │
│  │  └── Service Worker (PWA)                                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                               │                                     │
│                               │ HTTPS / WebSocket                   │
│                               ▼                                     │
├─────────────────────────────────────────────────────────────────────┤
│                      CAMADA 2: API GATEWAY                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Nginx / Cloudflare (Reverse Proxy)                        │   │
│  │  ├── Rate Limiting                                          │   │
│  │  ├── SSL Termination                                        │   │
│  │  ├── Load Balancing                                         │   │
│  │  ├── Static File Caching (CDN)                             │   │
│  │  └── WAF (Web Application Firewall)                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                               │                                     │
│                               ▼                                     │
├─────────────────────────────────────────────────────────────────────┤
│                    CAMADA 3: BACKEND SERVICES                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌────────────────────┬───────────────────┬──────────────────────┐ │
│  │  CORE API          │  EXPORT SERVICE   │  NOTIFICATION SVC    │ │
│  │  (NestJS)          │  (Puppeteer)      │  (Socket.io)         │ │
│  │  ──────────────    │  ───────────────  │  ──────────────────  │ │
│  │  • Auth            │  • PDF Gen        │  • WebSockets        │ │
│  │  • Projects CRUD   │  • Excel Gen      │  • Push Notif        │ │
│  │  • Checklists      │  • CSV Gen        │  • Email (SendGrid)  │ │
│  │  • Users           │  • Templates      │                      │ │
│  │  • Analytics       │  • Job Queue      │                      │ │
│  └────────┬───────────┴─────────┬─────────┴──────────────┬───────┘ │
│           │                     │                        │         │
│           │                     │                        │         │
│           ▼                     ▼                        ▼         │
├─────────────────────────────────────────────────────────────────────┤
│                      CAMADA 4: PERSISTÊNCIA                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┬──────────────────┬─────────────────────────┐  │
│  │  PostgreSQL     │  Redis           │  S3 / MinIO             │  │
│  │  (Dados)        │  (Cache/Queue)   │  (File Storage)         │  │
│  │  ─────────────  │  ──────────────  │  ─────────────────────  │  │
│  │  • users        │  • sessions      │  • evidences/           │  │
│  │  • projects     │  • rate_limits   │  • exports/             │  │
│  │  • items        │  • job_queue     │  • avatars/             │  │
│  │  • evidences    │                  │                         │  │
│  │  • audit_logs   │                  │                         │  │
│  └─────────────────┴──────────────────┴─────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Benefícios:**
- ✅ **Separação de Concerns:** Frontend, Backend, Storage
- ✅ **Escalabilidade Horizontal:** Múltiplas instâncias do Core API
- ✅ **Resiliência:** Export Service falha? API principal continua funcionando
- ✅ **Cache:** Redis para sessions, rate limiting, job queue
- ✅ **Storage:** S3 para arquivos (evidências) em vez de filesystem local
- ✅ **CDN:** Servir assets estáticos (JS, CSS, imagens) via Cloudflare

---

## 🔌 Design de APIs

### Princípios RESTful

| Princípio | Implementação |
|-----------|---------------|
| **Recursos como Substantivos** | `/projects`, `/items`, `/exports` (não `/getProject`) |
| **Verbos HTTP Semânticos** | GET (read), POST (create), PATCH (update), DELETE (delete) |
| **Status Codes Corretos** | 200 OK, 201 Created, 204 No Content, 400 Bad Request, 401/403 Auth, 404 Not Found, 500 Internal |
| **Versionamento** | `/api/v2/` (path-based, mais explícito) |
| **Paginação** | `?page=1&limit=20` |
| **Filtros** | `?status=active&sort=createdAt:desc` |
| **HATEOAS (opcional)** | Links para recursos relacionados no response |

### Estrutura de Endpoints v2

#### 1. **Autenticação**

```http
POST   /api/v2/auth/register         # Criar conta
POST   /api/v2/auth/login             # Login (retorna JWT)
POST   /api/v2/auth/refresh           # Refresh token
POST   /api/v2/auth/logout            # Logout (blacklist token)
POST   /api/v2/auth/forgot-password   # Recuperar senha
POST   /api/v2/auth/reset-password    # Resetar senha
GET    /api/v2/auth/me                # Info do usuário logado
```

#### 2. **Projetos**

```http
GET    /api/v2/projects                    # Listar projetos (com filtros)
POST   /api/v2/projects                    # Criar projeto
GET    /api/v2/projects/:id                # Detalhes do projeto
PATCH  /api/v2/projects/:id                # Atualizar projeto
DELETE /api/v2/projects/:id                # Deletar projeto
PATCH  /api/v2/projects/:id/archive        # Arquivar projeto

# Sub-recursos
GET    /api/v2/projects/:id/members        # Listar membros
POST   /api/v2/projects/:id/members        # Adicionar membro
DELETE /api/v2/projects/:id/members/:userId # Remover membro

GET    /api/v2/projects/:id/metrics        # Métricas do projeto
GET    /api/v2/projects/:id/top-risks      # Top riscos
GET    /api/v2/projects/:id/activity       # Feed de atividades
```

#### 3. **Checklists & Items**

```http
GET    /api/v2/checklists                  # Listar categorias de checklists
GET    /api/v2/checklists/:categoryId      # Itens de uma categoria

# Items de um projeto específico
GET    /api/v2/projects/:id/items          # Listar todos os items (com filtros)
GET    /api/v2/projects/:id/items/:itemId  # Detalhes de um item
PATCH  /api/v2/projects/:id/items/:itemId  # Atualizar estado do item

# Comentários
POST   /api/v2/items/:itemId/comments      # Adicionar comentário
GET    /api/v2/items/:itemId/comments      # Listar comentários
```

#### 4. **Evidências (Upload de Arquivos)**

```http
POST   /api/v2/items/:itemId/evidences     # Upload de arquivo
GET    /api/v2/items/:itemId/evidences     # Listar evidências
DELETE /api/v2/evidences/:evidenceId       # Deletar evidência

# Download com URL assinada (expirável)
GET    /api/v2/evidences/:evidenceId/download  # Redireciona para S3 signed URL
```

#### 5. **Exportações**

```http
POST   /api/v2/projects/:id/export/pdf     # Gerar PDF (async)
POST   /api/v2/projects/:id/export/excel   # Gerar Excel (async)
POST   /api/v2/projects/:id/export/json    # Export JSON (sync)

GET    /api/v2/exports/:jobId              # Status da exportação
GET    /api/v2/exports/:jobId/download     # Download do arquivo gerado

GET    /api/v2/projects/:id/exports        # Histórico de exportações
```

#### 6. **Analytics**

```http
GET    /api/v2/projects/:id/analytics/coverage     # Cobertura por categoria
GET    /api/v2/projects/:id/analytics/workflow     # Distribuição por fase
GET    /api/v2/projects/:id/analytics/trends       # Tendências ao longo do tempo
```

#### 7. **Usuários**

```http
GET    /api/v2/users                       # Listar usuários (admin only)
GET    /api/v2/users/:id                   # Detalhes de um usuário
PATCH  /api/v2/users/:id                   # Atualizar perfil
DELETE /api/v2/users/:id                   # Deletar usuário (admin only)
```

#### 8. **Webhooks (Integrações)**

```http
GET    /api/v2/webhooks                    # Listar webhooks do projeto
POST   /api/v2/webhooks                    # Criar webhook
DELETE /api/v2/webhooks/:id                # Deletar webhook

# Webhook será chamado em eventos:
# - project.updated
# - item.status_changed
# - evidence.uploaded
# - export.completed
```

### Response Padrão

**Success (200 OK):**

```json
{
  "success": true,
  "data": {
    "id": "proj_abc123",
    "name": "API de Pagamentos v2.1",
    "status": "active",
    "progress": 65,
    "createdAt": "2025-11-09T10:00:00Z"
  },
  "meta": {
    "timestamp": "2025-11-09T10:30:00Z",
    "version": "2.0"
  }
}
```

**Error (400 Bad Request):**

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Dados inválidos",
    "details": [
      {
        "field": "name",
        "message": "Nome deve ter pelo menos 3 caracteres"
      },
      {
        "field": "teamMembers",
        "message": "Deve ter pelo menos 1 membro"
      }
    ]
  },
  "meta": {
    "timestamp": "2025-11-09T10:30:00Z",
    "requestId": "req_xyz789"
  }
}
```

**Paginação (200 OK):**

```json
{
  "success": true,
  "data": [
    { "id": "proj_1", "name": "Projeto 1" },
    { "id": "proj_2", "name": "Projeto 2" }
  ],
  "pagination": {
    "total": 45,
    "page": 1,
    "limit": 20,
    "pages": 3,
    "hasNext": true,
    "hasPrev": false
  },
  "meta": {
    "timestamp": "2025-11-09T10:30:00Z"
  }
}
```

---

## 🗄️ Banco de Dados

### Migração: lowdb (JSON) → PostgreSQL

**Justificativa:**
- ✅ **ACID Transactions:** Garantia de consistência
- ✅ **Concorrência:** Múltiplos usuários sem conflitos
- ✅ **Índices:** Queries rápidas (busca, filtros, ordenação)
- ✅ **Relações:** Foreign keys, joins
- ✅ **Backup:** Ferramentas maduras (pg_dump, replicação)
- ✅ **Escalabilidade:** Suporta milhões de registros

### Schema do Banco de Dados

**Diagrama ER (Entity-Relationship):**

```sql
┌─────────────────┐         ┌─────────────────────┐         ┌──────────────────┐
│     users       │         │    projects         │         │  checklist_items │
├─────────────────┤         ├─────────────────────┤         ├──────────────────┤
│ id (UUID) PK    │         │ id (UUID) PK        │         │ id (UUID) PK     │
│ email (unique)  │         │ name                │         │ category_id      │
│ password_hash   │         │ description         │         │ section_id       │
│ name            │         │ status              │         │ title            │
│ role (enum)     │         │ created_by FK       │◄───────┤│ description      │
│ created_at      │         │ created_at          │         │ guide_content    │
│ updated_at      │         │ updated_at          │         │ created_at       │
└────────┬────────┘         └──────────┬──────────┘         └──────────────────┘
         │                             │
         │                             │
         │                             │
         │         ┌───────────────────┴───────────────┐
         │         │                                   │
         │         ▼                                   ▼
         │  ┌─────────────────────┐         ┌─────────────────────┐
         │  │  project_members    │         │    item_states      │
         │  ├─────────────────────┤         ├─────────────────────┤
         │  │ id (UUID) PK        │         │ id (UUID) PK        │
         └─►│ project_id FK       │         │ project_id FK       │
            │ user_id FK          │         │ item_id FK          │
            │ role (enum)         │         │ checked             │
            │ joined_at           │         │ status (enum)       │
            └─────────────────────┘         │ severity (enum)     │
                                            │ stage (enum)        │
                      ┌─────────────────────┤ notes               │
                      │                     │ assignee_id FK      │
                      │                     │ priority (enum)     │
                      │                     │ created_at          │
                      │                     │ updated_at          │
                      │                     └──────────┬──────────┘
                      │                                │
                      ▼                                ▼
            ┌─────────────────────┐         ┌─────────────────────┐
            │    evidences        │         │     comments        │
            ├─────────────────────┤         ├─────────────────────┤
            │ id (UUID) PK        │         │ id (UUID) PK        │
            │ item_state_id FK    │         │ item_state_id FK    │
            │ filename            │         │ user_id FK          │
            │ original_name       │         │ text                │
            │ mime_type           │         │ mentions (array)    │
            │ size_bytes          │         │ created_at          │
            │ storage_path        │         │ updated_at          │
            │ uploaded_by FK      │         └─────────────────────┘
            │ uploaded_at         │
            └─────────────────────┘
```

### SQL Schema (PostgreSQL)

```sql
-- Extensões
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enums
CREATE TYPE user_role AS ENUM ('admin', 'editor', 'viewer');
CREATE TYPE project_status AS ENUM ('active', 'completed', 'archived');
CREATE TYPE item_status AS ENUM ('not_tested', 'passed', 'failed', 'na');
CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE stage AS ENUM ('recon', 'testing', 'access', 'report', 'mitigate');
CREATE TYPE priority AS ENUM ('p0', 'p1', 'p2', 'p3');

-- Tabela: users
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  name VARCHAR(100) NOT NULL,
  role user_role DEFAULT 'editor',
  avatar_url VARCHAR(500),
  mfa_enabled BOOLEAN DEFAULT FALSE,
  mfa_secret VARCHAR(100),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  last_login_at TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);

-- Tabela: projects
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name VARCHAR(100) NOT NULL,
  description TEXT,
  status project_status DEFAULT 'active',
  metadata JSONB DEFAULT '{}',
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_projects_status ON projects(status);
CREATE INDEX idx_projects_created_by ON projects(created_by);

-- Tabela: project_members
CREATE TABLE project_members (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  role user_role DEFAULT 'editor',
  joined_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(project_id, user_id)
);

CREATE INDEX idx_project_members_project ON project_members(project_id);
CREATE INDEX idx_project_members_user ON project_members(user_id);

-- Tabela: checklist_items (dados estáticos)
CREATE TABLE checklist_items (
  id VARCHAR(50) PRIMARY KEY,  -- Ex: "owasp-web::a01::a01-1"
  category_id VARCHAR(50) NOT NULL,
  section_id VARCHAR(50) NOT NULL,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  guide_content JSONB,  -- { overview, impact, detection, tools, etc. }
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_checklist_category ON checklist_items(category_id);

-- Tabela: item_states (estado por projeto)
CREATE TABLE item_states (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  item_id VARCHAR(50) REFERENCES checklist_items(id),
  checked BOOLEAN DEFAULT FALSE,
  status item_status DEFAULT 'not_tested',
  severity severity DEFAULT 'medium',
  stage stage DEFAULT 'recon',
  priority priority DEFAULT 'p2',
  notes TEXT,
  evidence_narrative TEXT,
  evidence_checklist JSONB DEFAULT '{}'::JSONB,
  assignee_id UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(project_id, item_id)
);

CREATE INDEX idx_item_states_project ON item_states(project_id);
CREATE INDEX idx_item_states_status ON item_states(status);
CREATE INDEX idx_item_states_assignee ON item_states(assignee_id);

-- Tabela: evidences
CREATE TABLE evidences (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  item_state_id UUID REFERENCES item_states(id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  original_name VARCHAR(255) NOT NULL,
  mime_type VARCHAR(100),
  size_bytes INTEGER,
  storage_path VARCHAR(500),
  uploaded_by UUID REFERENCES users(id),
  uploaded_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_evidences_item_state ON evidences(item_state_id);

-- Tabela: comments
CREATE TABLE comments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  item_state_id UUID REFERENCES item_states(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  text TEXT NOT NULL,
  mentions UUID[] DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_comments_item_state ON comments(item_state_id);

-- Tabela: audit_logs
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(100) NOT NULL,  -- 'create_project', 'update_item', etc.
  resource_type VARCHAR(50),
  resource_id UUID,
  changes JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Triggers para updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_item_states_updated_at BEFORE UPDATE ON item_states
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_comments_updated_at BEFORE UPDATE ON comments
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

### TypeORM Entities (Exemplo)

```typescript
// src/projects/entities/project.entity.ts

import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  JoinColumn
} from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { ProjectMember } from './project-member.entity';
import { ItemState } from '../../checklists/entities/item-state.entity';

export enum ProjectStatus {
  ACTIVE = 'active',
  COMPLETED = 'completed',
  ARCHIVED = 'archived'
}

@Entity('projects')
export class Project {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 100 })
  name: string;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({
    type: 'enum',
    enum: ProjectStatus,
    default: ProjectStatus.ACTIVE
  })
  status: ProjectStatus;

  @Column({ type: 'jsonb', default: {} })
  metadata: Record<string, any>;

  @ManyToOne(() => User, { nullable: true })
  @JoinColumn({ name: 'created_by' })
  createdBy: User;

  @OneToMany(() => ProjectMember, member => member.project)
  members: ProjectMember[];

  @OneToMany(() => ItemState, item => item.project)
  items: ItemState[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

---

## 📤 Serviço de Exportação

### Arquitetura Assíncrona com Job Queue

**Problema:** Gerar PDFs de 50+ páginas pode levar 10-30 segundos. Bloquear a request HTTP não é viável.

**Solução:** Job Queue com Bull (Redis).

```
Cliente                API Backend           Export Service         Redis Queue
  │                        │                       │                     │
  │  POST /export/pdf      │                       │                     │
  ├───────────────────────►│                       │                     │
  │                        │  Enqueue Job          │                     │
  │                        ├──────────────────────────────────────────►  │
  │  202 Accepted          │                       │                     │
  │  { jobId: "abc123" }   │                       │                     │
  │◄───────────────────────┤                       │                     │
  │                        │                       │  Pop Job            │
  │                        │                       │◄────────────────────┤
  │                        │                       │                     │
  │                        │                       │  Generate PDF       │
  │                        │                       │  (Puppeteer)        │
  │                        │                       │  ⏳ 15s              │
  │                        │                       │                     │
  │                        │                       │  Upload to S3       │
  │                        │                       │  ──────────►        │
  │                        │                       │                     │
  │                        │  Job Completed        │                     │
  │                        │◄──────────────────────┤                     │
  │                        │  Update DB            │                     │
  │                        │                       │                     │
  │  GET /exports/abc123   │                       │                     │
  ├───────────────────────►│                       │                     │
  │  200 OK                │                       │                     │
  │  { status: "completed",│                       │                     │
  │    downloadUrl: "..." }│                       │                     │
  │◄───────────────────────┤                       │                     │
  │                        │                       │                     │
  │  GET /downloads/...pdf │                       │                     │
  ├───────────────────────►│  S3 Signed URL        │                     │
  │  302 Redirect          │◄──────────────────────┤                     │
  │◄───────────────────────┤                       │                     │
  │                        │                       │                     │
  │  ⬇️ Download PDF       │                       │                     │
```

### Implementação com Bull

```typescript
// src/exports/exports.service.ts

import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bull';
import { Queue } from 'bull';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Export } from './entities/export.entity';
import { ExportFormat, ExportStatus } from './enums';

@Injectable()
export class ExportsService {
  constructor(
    @InjectQueue('exports') private exportsQueue: Queue,
    @InjectRepository(Export) private exportsRepo: Repository<Export>
  ) {}

  async createPdfExport(projectId: string, options: any) {
    // Criar registro no banco
    const exportRecord = this.exportsRepo.create({
      projectId,
      format: ExportFormat.PDF,
      status: ExportStatus.PENDING,
      options
    });
    await this.exportsRepo.save(exportRecord);

    // Enfileirar job
    await this.exportsQueue.add('generate-pdf', {
      exportId: exportRecord.id,
      projectId,
      options
    });

    return {
      jobId: exportRecord.id,
      status: ExportStatus.PENDING,
      estimatedTime: 30  // segundos
    };
  }

  async getExportStatus(jobId: string) {
    const exportRecord = await this.exportsRepo.findOne({ where: { id: jobId } });
    if (!exportRecord) {
      throw new NotFoundException('Export não encontrado');
    }

    return {
      status: exportRecord.status,
      downloadUrl: exportRecord.downloadUrl,
      fileSize: exportRecord.fileSize,
      pages: exportRecord.metadata?.pages,
      createdAt: exportRecord.createdAt,
      completedAt: exportRecord.completedAt
    };
  }
}
```

**Processor (Worker):**

```typescript
// src/exports/processors/pdf.processor.ts

import { Process, Processor } from '@nestjs/bull';
import { Job } from 'bull';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Export } from '../entities/export.entity';
import { ExportStatus } from '../enums';
import { PdfGenerator } from '../generators/pdf.generator';
import { S3Service } from '../../common/services/s3.service';

@Processor('exports')
@Injectable()
export class PdfProcessor {
  constructor(
    @InjectRepository(Export) private exportsRepo: Repository<Export>,
    private pdfGenerator: PdfGenerator,
    private s3Service: S3Service
  ) {}

  @Process('generate-pdf')
  async handlePdfGeneration(job: Job) {
    const { exportId, projectId, options } = job.data;

    try {
      // Atualizar status para "processing"
      await this.exportsRepo.update(exportId, { status: ExportStatus.PROCESSING });

      // Buscar dados do projeto
      const projectData = await this.fetchProjectData(projectId);

      // Gerar PDF
      const pdfBuffer = await this.pdfGenerator.generate(projectData, options);

      // Upload para S3
      const filename = `exports/${projectId}/report_${exportId}.pdf`;
      const uploadResult = await this.s3Service.upload(filename, pdfBuffer, 'application/pdf');

      // Gerar URL assinada (expira em 7 dias)
      const downloadUrl = await this.s3Service.getSignedUrl(filename, 7 * 24 * 60 * 60);

      // Atualizar registro
      await this.exportsRepo.update(exportId, {
        status: ExportStatus.COMPLETED,
        downloadUrl,
        fileSize: pdfBuffer.length,
        metadata: {
          pages: pdfBuffer.toString().match(/\/Type\s*\/Page[^s]/g)?.length || 0
        },
        completedAt: new Date()
      });

      return { success: true };
    } catch (error) {
      await this.exportsRepo.update(exportId, {
        status: ExportStatus.FAILED,
        error: error.message
      });
      throw error;
    }
  }

  private async fetchProjectData(projectId: string) {
    // Buscar projeto + items + evidências do banco
    // ...
  }
}
```

**PDF Generator (Puppeteer):**

```typescript
// src/exports/generators/pdf.generator.ts

import { Injectable } from '@nestjs/common';
import puppeteer from 'puppeteer';
import { renderTemplate } from '../templates/executive.template';

@Injectable()
export class PdfGenerator {
  async generate(projectData: any, options: any): Promise<Buffer> {
    // Renderizar HTML do template
    const html = renderTemplate(projectData, options);

    // Puppeteer headless Chrome
    const browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });

    // Gerar PDF
    const pdfBuffer = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: {
        top: '20mm',
        right: '15mm',
        bottom: '20mm',
        left: '15mm'
      },
      displayHeaderFooter: true,
      headerTemplate: `
        <div style="font-size: 10px; text-align: center; width: 100%;">
          ${options.company || 'AppSec Dashboard'} — Relatório Confidencial
        </div>
      `,
      footerTemplate: `
        <div style="font-size: 10px; text-align: center; width: 100%;">
          Página <span class="pageNumber"></span> de <span class="totalPages"></span>
        </div>
      `
    });

    await browser.close();

    return pdfBuffer;
  }
}
```

---

## ☁️ Infraestrutura & DevOps

### Stack de Infraestrutura

```yaml
# docker-compose.yml (Desenvolvimento Local)

version: '3.9'

services:
  # Frontend (React)
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.dev
    ports:
      - '3000:3000'
    volumes:
      - ./frontend/src:/app/src
    environment:
      - VITE_API_URL=http://localhost:4000
    depends_on:
      - backend

  # Backend (NestJS)
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.dev
    ports:
      - '4000:4000'
    volumes:
      - ./backend/src:/app/src
    environment:
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/appsec_dashboard
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=super-secret-dev-key
      - AWS_S3_BUCKET=appsec-dev
    depends_on:
      - postgres
      - redis

  # PostgreSQL
  postgres:
    image: postgres:16-alpine
    ports:
      - '5432:5432'
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=appsec_dashboard
    volumes:
      - postgres_data:/var/lib/postgresql/data

  # Redis (Cache & Queue)
  redis:
    image: redis:7-alpine
    ports:
      - '6379:6379'
    volumes:
      - redis_data:/data

  # MinIO (S3-compatible storage para dev)
  minio:
    image: minio/minio
    ports:
      - '9000:9000'
      - '9001:9001'
    environment:
      - MINIO_ROOT_USER=minioadmin
      - MINIO_ROOT_PASSWORD=minioadmin
    command: server /data --console-address ":9001"
    volumes:
      - minio_data:/data

volumes:
  postgres_data:
  redis_data:
  minio_data:
```

### CI/CD Pipeline (GitHub Actions)

```yaml
# .github/workflows/ci-cd.yml

name: CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test-backend:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install dependencies
        working-directory: ./backend
        run: npm ci
      - name: Run tests
        working-directory: ./backend
        run: npm run test:cov
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  test-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install dependencies
        working-directory: ./frontend
        run: npm ci
      - name: Run tests
        working-directory: ./frontend
        run: npm run test:unit
      - name: Run E2E tests
        working-directory: ./frontend
        run: npx playwright test

  build-and-deploy:
    needs: [test-backend, test-frontend]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Build Frontend
      - name: Build Frontend
        working-directory: ./frontend
        run: |
          npm ci
          npm run build

      # Build Backend Docker Image
      - name: Build Backend Image
        run: |
          docker build -t appsec-backend:${{ github.sha }} ./backend
          docker tag appsec-backend:${{ github.sha }} appsec-backend:latest

      # Deploy to AWS ECS / Kubernetes / VPS
      - name: Deploy to Production
        run: |
          # Exemplo: Deploy via kubectl ou AWS CLI
          echo "Deploying to production..."
```

### Deployment (Kubernetes)

```yaml
# k8s/backend-deployment.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: appsec-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: appsec-backend
  template:
    metadata:
      labels:
        app: appsec-backend
    spec:
      containers:
      - name: backend
        image: appsec-backend:latest
        ports:
        - containerPort: 4000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: appsec-secrets
              key: database-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: appsec-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 4000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 4000
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: appsec-backend-service
spec:
  selector:
    app: appsec-backend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 4000
  type: LoadBalancer
```

---

## ⚡ Performance & Escalabilidade

### Otimizações de Performance

| Técnica | Implementação | Ganho Esperado |
|---------|---------------|----------------|
| **Code Splitting** | Vite `manualChunks` | -40% bundle inicial |
| **Lazy Loading** | React.lazy() para rotas | -50% tempo First Paint |
| **Image Optimization** | WebP, lazy loading, srcset | -60% peso de imagens |
| **API Response Caching** | Redis com TTL 5min | -80% latência em reads |
| **Database Indexing** | Índices em colunas filtráveis | -90% tempo de query |
| **CDN** | Cloudflare para assets | -70% latência global |
| **Compression** | Gzip/Brotli no Nginx | -70% tamanho de transferência |
| **HTTP/2** | Nginx com HTTP/2 habilitado | +30% velocidade de carregamento |

### Benchmarks Alvo

| Métrica | Versão Atual | Versão v2.0 | Melhoria |
|---------|--------------|-------------|----------|
| **First Contentful Paint** | 2.5s | 0.8s | 68% ⬇️ |
| **Time to Interactive** | 4.2s | 1.5s | 64% ⬇️ |
| **Bundle Size (gzipped)** | 850 KB | 280 KB | 67% ⬇️ |
| **API Response Time (p95)** | 800ms | 150ms | 81% ⬇️ |
| **Database Query Time (p95)** | 300ms | 30ms | 90% ⬇️ |
| **Lighthouse Score** | 65 | 95+ | +30 pts |

---

## 📊 Comparação: Antes vs Depois

### Arquitetura

| Aspecto | Versão Atual (v1.x) | Versão Proposta (v2.0) |
|---------|---------------------|------------------------|
| **Frontend** | Vanilla JS | React + TypeScript |
| **Backend** | Express.js | NestJS |
| **Database** | lowdb (JSON file) | PostgreSQL |
| **Cache** | Nenhum | Redis |
| **Storage** | Filesystem local | S3 / MinIO |
| **Auth** | ❌ Nenhuma | JWT + RBAC |
| **Real-time** | ❌ Não | WebSockets |
| **Job Queue** | ❌ Não | Bull (Redis) |
| **API Docs** | ❌ Não | Swagger/OpenAPI |
| **Testing** | Vitest básico | Jest + Playwright E2E |
| **CI/CD** | ❌ Manual | GitHub Actions |
| **Deployment** | Node local | Kubernetes / Docker |

### Funcionalidades

| Feature | v1.x | v2.0 |
|---------|------|------|
| Múltiplos projetos | ❌ | ✅ |
| Dashboard analítico | Básico (4 cards) | Avançado (gráficos, insights) |
| Colaboração multi-user | ❌ | ✅ (atribuição, comentários, RBAC) |
| Exportação PDF | Print to PDF (ruim) | Templates profissionais + async |
| Exportação Excel/CSV | ❌ | ✅ |
| API pública (JSON) | ❌ | ✅ |
| Webhooks | ❌ | ✅ |
| Modo offline (PWA) | ❌ | ✅ |
| Multi-idioma (i18n) | ❌ | ✅ (pt-BR, en-US, es-ES) |
| Mobile responsivo | Parcial (quebra <768px) | Mobile-first |
| Acessibilidade (WCAG) | Não | AA compliant |

### Segurança

| Controle | v1.x | v2.0 |
|----------|------|------|
| Autenticação | ❌ | JWT + MFA |
| Autorização | ❌ | RBAC (Admin/Editor/Viewer) |
| Sanitização de inputs | ❌ | DOMPurify + Joi/Zod |
| Validação de uploads | ❌ | MIME whitelist + size limit |
| Rate limiting | ❌ | Por IP e por usuário |
| Auditoria | ❌ | Logs completos (quem/quando/o quê) |
| Criptografia de dados | ❌ | Senhas (bcrypt), sensitive fields |
| CSP | ❌ | Habilitado |
| CORS | ❌ | Configurado |

---

## 🚀 Próximos Passos

1. **Prototipar frontend** com React + Radix UI (1 sprint)
2. **Migrar backend** para NestJS (2 sprints)
3. **Setup PostgreSQL** e migrar dados de state.json (1 sprint)
4. **Implementar Auth JWT** (1 sprint)
5. **Desenvolver Dashboard analítico** (2 sprints)
6. **Implementar serviço de exportação PDF** (2 sprints)
7. **Testes E2E completos** (1 sprint)
8. **Deploy em staging** (1 sprint)
9. **Validação com usuários** (2 semanas)
10. **Deploy em produção** (1 sprint)

---

**Documento vivo** — Atualizado conforme arquitetura evolui.

**Contato:** Equipe de Engenharia | eng@appsec-dashboard.com
