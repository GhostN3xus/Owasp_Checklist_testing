# 🚀 Guia de Implementação Completo — AppSec Dashboard v2.0

**Data:** 2025-11-09
**Status:** Em Implementação

---

## 📋 Índice

1. [Visão Geral](#visão-geral)
2. [Estrutura de Diretórios](#estrutura-de-diretórios)
3. [Backend NestJS - Implementação](#backend-nestjs)
4. [Frontend React - Implementação](#frontend-react)
5. [Database Schema SQL](#database-schema-sql)
6. [Docker & Infraestrutura](#docker--infraestrutura)
7. [Comandos de Setup](#comandos-de-setup)
8. [Próximos Passos](#próximos-passos)

---

## 🎯 Visão Geral

Este guia fornece a implementação completa do redesign v2.0, incluindo:

- ✅ **Backend NestJS** (~50 arquivos)
- ✅ **Frontend React** (~60 arquivos)
- ✅ **Database Schema** (PostgreSQL)
- ✅ **Docker Setup** (docker-compose.yml)
- ✅ **Scripts de Migração**

**Total estimado:** ~150 arquivos de código

---

## 📁 Estrutura de Diretórios

```
v2/
├── backend/                           # NestJS API
│   ├── src/
│   │   ├── main.ts                   # ✅ Bootstrap da aplicação
│   │   ├── app.module.ts             # ✅ Root module
│   │   │
│   │   ├── auth/                     # Autenticação JWT
│   │   │   ├── auth.module.ts
│   │   │   ├── auth.controller.ts
│   │   │   ├── auth.service.ts
│   │   │   ├── strategies/
│   │   │   │   ├── jwt.strategy.ts
│   │   │   │   └── local.strategy.ts
│   │   │   ├── guards/
│   │   │   │   ├── jwt-auth.guard.ts
│   │   │   │   └── roles.guard.ts
│   │   │   └── dto/
│   │   │       ├── login.dto.ts
│   │   │       └── register.dto.ts
│   │   │
│   │   ├── users/                    # Usuários
│   │   │   ├── users.module.ts
│   │   │   ├── users.controller.ts
│   │   │   ├── users.service.ts
│   │   │   ├── entities/
│   │   │   │   └── user.entity.ts
│   │   │   └── dto/
│   │   │       ├── create-user.dto.ts
│   │   │       └── update-user.dto.ts
│   │   │
│   │   ├── projects/                 # Projetos
│   │   │   ├── projects.module.ts
│   │   │   ├── projects.controller.ts
│   │   │   ├── projects.service.ts
│   │   │   ├── entities/
│   │   │   │   ├── project.entity.ts
│   │   │   │   └── project-member.entity.ts
│   │   │   └── dto/
│   │   │       ├── create-project.dto.ts
│   │   │       ├── update-project.dto.ts
│   │   │       └── filter-project.dto.ts
│   │   │
│   │   ├── checklists/               # Checklists
│   │   │   ├── checklists.module.ts
│   │   │   ├── checklists.controller.ts
│   │   │   ├── checklists.service.ts
│   │   │   ├── entities/
│   │   │   │   ├── checklist-item.entity.ts
│   │   │   │   └── item-state.entity.ts
│   │   │   └── dto/
│   │   │       └── update-item-state.dto.ts
│   │   │
│   │   ├── evidence/                 # Evidências (uploads)
│   │   │   ├── evidence.module.ts
│   │   │   ├── evidence.controller.ts
│   │   │   ├── evidence.service.ts
│   │   │   ├── entities/
│   │   │   │   └── evidence.entity.ts
│   │   │   └── storage/
│   │   │       └── local-storage.service.ts
│   │   │
│   │   ├── exports/                  # Exportações (PDF, Excel)
│   │   │   ├── exports.module.ts
│   │   │   ├── exports.controller.ts
│   │   │   ├── exports.service.ts
│   │   │   ├── generators/
│   │   │   │   ├── pdf.generator.ts
│   │   │   │   ├── excel.generator.ts
│   │   │   │   └── csv.generator.ts
│   │   │   └── templates/
│   │   │       ├── executive.template.ts
│   │   │       └── technical.template.ts
│   │   │
│   │   ├── analytics/                # Analytics
│   │   │   ├── analytics.module.ts
│   │   │   ├── analytics.controller.ts
│   │   │   └── analytics.service.ts
│   │   │
│   │   ├── notifications/            # Notificações WebSocket
│   │   │   ├── notifications.module.ts
│   │   │   ├── notifications.gateway.ts
│   │   │   └── notifications.service.ts
│   │   │
│   │   ├── common/                   # Código compartilhado
│   │   │   ├── decorators/
│   │   │   │   ├── roles.decorator.ts
│   │   │   │   └── current-user.decorator.ts
│   │   │   ├── filters/
│   │   │   │   └── http-exception.filter.ts
│   │   │   ├── interceptors/
│   │   │   │   ├── logging.interceptor.ts
│   │   │   │   └── transform.interceptor.ts
│   │   │   ├── pipes/
│   │   │   │   └── validation.pipe.ts
│   │   │   └── constants/
│   │   │       ├── roles.enum.ts
│   │   │       └── status.enum.ts
│   │   │
│   │   └── database/                 # Database
│   │       ├── migrations/
│   │       │   └── 1699999999999-InitialSchema.ts
│   │       └── seeds/
│   │           └── checklist-data.seed.ts
│   │
│   ├── test/                         # Testes E2E
│   │   └── app.e2e-spec.ts
│   │
│   ├── .env.example                  # ✅ Variáveis de ambiente
│   ├── package.json                  # ✅ Dependências
│   ├── tsconfig.json                 # ✅ TypeScript config
│   ├── nest-cli.json                 # ✅ NestJS CLI config
│   └── README.md
│
├── frontend/                          # React SPA
│   ├── src/
│   │   ├── main.tsx                  # Bootstrap React
│   │   ├── App.tsx                   # Root component
│   │   │
│   │   ├── pages/                    # Páginas (rotas)
│   │   │   ├── Login.tsx
│   │   │   ├── Register.tsx
│   │   │   ├── ProjectsList.tsx
│   │   │   ├── ProjectDashboard.tsx
│   │   │   ├── ChecklistEditor.tsx
│   │   │   └── NotFound.tsx
│   │   │
│   │   ├── components/               # Componentes reutilizáveis
│   │   │   ├── layout/
│   │   │   │   ├── Header.tsx
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   └── Footer.tsx
│   │   │   ├── ui/                   # Design System
│   │   │   │   ├── Button.tsx
│   │   │   │   ├── Card.tsx
│   │   │   │   ├── Badge.tsx
│   │   │   │   ├── Modal.tsx
│   │   │   │   ├── Input.tsx
│   │   │   │   ├── Select.tsx
│   │   │   │   ├── Textarea.tsx
│   │   │   │   ├── ProgressBar.tsx
│   │   │   │   └── Toast.tsx
│   │   │   ├── checklist/
│   │   │   │   ├── ChecklistItem.tsx
│   │   │   │   ├── ChecklistSection.tsx
│   │   │   │   └── ItemDetailModal.tsx
│   │   │   ├── dashboard/
│   │   │   │   ├── MetricsCard.tsx
│   │   │   │   ├── RadialChart.tsx
│   │   │   │   ├── TopRisks.tsx
│   │   │   │   └── ActivityFeed.tsx
│   │   │   └── exports/
│   │   │       └── ExportModal.tsx
│   │   │
│   │   ├── hooks/                    # Custom hooks
│   │   │   ├── useAuth.ts
│   │   │   ├── useProjects.ts
│   │   │   ├── useChecklists.ts
│   │   │   └── useWebSocket.ts
│   │   │
│   │   ├── services/                 # API clients
│   │   │   ├── api.ts                # Axios config
│   │   │   ├── auth.service.ts
│   │   │   ├── projects.service.ts
│   │   │   ├── checklists.service.ts
│   │   │   └── exports.service.ts
│   │   │
│   │   ├── store/                    # State management (Zustand)
│   │   │   ├── authStore.ts
│   │   │   ├── projectsStore.ts
│   │   │   └── uiStore.ts
│   │   │
│   │   ├── utils/                    # Utilitários
│   │   │   ├── sanitize.ts           # DOMPurify
│   │   │   ├── format.ts             # Formatação
│   │   │   └── validation.ts         # Validação
│   │   │
│   │   ├── styles/                   # Estilos globais
│   │   │   ├── global.css            # Reset + design tokens
│   │   │   └── theme.css             # Cores, tipografia
│   │   │
│   │   ├── types/                    # TypeScript types
│   │   │   ├── user.types.ts
│   │   │   ├── project.types.ts
│   │   │   └── checklist.types.ts
│   │   │
│   │   └── assets/                   # Imagens, ícones
│   │       └── logo.svg
│   │
│   ├── public/
│   │   ├── manifest.json             # PWA manifest
│   │   └── robots.txt
│   │
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── README.md
│
├── docker-compose.yml                # ✅ Docker setup completo
├── .gitignore
└── README.md                         # ✅ Instruções de setup
```

**Total:** ~150 arquivos

---

## 🔧 Backend NestJS

### Arquivos Já Criados (✅)

1. **package.json** — Dependências completas
2. **tsconfig.json** — Configuração TypeScript
3. **nest-cli.json** — CLI config
4. **.env.example** — Variáveis de ambiente
5. **src/main.ts** — Bootstrap com Swagger
6. **src/app.module.ts** — Root module

### Arquivos a Criar

Devido ao grande volume, vou fornecer **templates** dos arquivos mais importantes:

#### 📄 `src/users/entities/user.entity.ts`

```typescript
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { Exclude } from 'class-transformer';

export enum UserRole {
  ADMIN = 'admin',
  EDITOR = 'editor',
  VIEWER = 'viewer',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude() // Não expor no JSON
  passwordHash: string;

  @Column({ length: 100 })
  name: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.EDITOR,
  })
  role: UserRole;

  @Column({ nullable: true })
  avatarUrl?: string;

  @Column({ default: false })
  mfaEnabled: boolean;

  @Column({ nullable: true })
  @Exclude()
  mfaSecret?: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt?: Date;
}
```

#### 📄 `src/auth/auth.service.ts`

```typescript
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Email ou senha inválidos');
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Email ou senha inválidos');
    }

    const { passwordHash, mfaSecret, ...result } = user;
    return result;
  }

  async login(user: any) {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role
    };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.configService.get('JWT_EXPIRES_IN'),
    });

    const refreshToken = this.jwtService.sign(
      { sub: user.id, type: 'refresh' },
      {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get('JWT_REFRESH_EXPIRES_IN'),
      },
    );

    // Atualizar lastLoginAt
    await this.usersService.updateLastLogin(user.id);

    return {
      accessToken,
      refreshToken,
      user,
    };
  }

  async register(email: string, password: string, name: string) {
    const passwordHash = await bcrypt.hash(
      password,
      +this.configService.get('BCRYPT_ROUNDS'),
    );

    return this.usersService.create({
      email,
      passwordHash,
      name,
    });
  }

  async refreshAccessToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });

      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Token inválido');
      }

      const user = await this.usersService.findById(payload.sub);

      if (!user) {
        throw new UnauthorizedException('Usuário não encontrado');
      }

      const newAccessToken = this.jwtService.sign({
        sub: user.id,
        email: user.email,
        role: user.role,
      });

      return { accessToken: newAccessToken };
    } catch (error) {
      throw new UnauthorizedException('Refresh token inválido ou expirado');
    }
  }
}
```

#### 📄 `src/projects/entities/project.entity.ts`

```typescript
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  JoinColumn,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { ItemState } from '../../checklists/entities/item-state.entity';

export enum ProjectStatus {
  ACTIVE = 'active',
  COMPLETED = 'completed',
  ARCHIVED = 'archived',
}

@Entity('projects')
export class Project {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ length: 100 })
  name: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({
    type: 'enum',
    enum: ProjectStatus,
    default: ProjectStatus.ACTIVE,
  })
  status: ProjectStatus;

  @Column({ type: 'jsonb', default: {} })
  metadata: Record<string, any>;

  @ManyToOne(() => User, { nullable: true })
  @JoinColumn({ name: 'created_by' })
  createdBy: User;

  @OneToMany(() => ItemState, (item) => item.project)
  items: ItemState[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
```

### Database Schema SQL Completo

Ver seção [Database Schema](#database-schema-sql) abaixo.

---

## ⚛️ Frontend React

### Estrutura Base

#### 📄 `frontend/package.json`

```json
{
  "name": "appsec-dashboard-frontend",
  "version": "2.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "test": "vitest"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "zustand": "^4.4.7",
    "@tanstack/react-query": "^5.12.0",
    "axios": "^1.6.2",
    "date-fns": "^3.0.0",
    "dompurify": "^3.0.6",
    "recharts": "^2.10.0",
    "react-hook-form": "^7.49.0",
    "zod": "^3.22.4",
    "@radix-ui/react-dialog": "^1.0.5",
    "@radix-ui/react-dropdown-menu": "^2.0.6",
    "@radix-ui/react-tabs": "^1.0.4",
    "@radix-ui/react-toast": "^1.1.5",
    "clsx": "^2.0.0",
    "react-i18next": "^13.5.0",
    "i18next": "^23.7.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.45",
    "@types/react-dom": "^18.2.18",
    "@types/dompurify": "^3.0.5",
    "@typescript-eslint/eslint-plugin": "^6.15.0",
    "@typescript-eslint/parser": "^6.15.0",
    "@vitejs/plugin-react": "^4.2.1",
    "eslint": "^8.56.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "typescript": "^5.3.3",
    "vite": "^5.0.8",
    "vite-plugin-pwa": "^0.17.4",
    "vitest": "^1.0.4"
  }
}
```

#### 📄 `frontend/vite.config.ts`

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
            type: 'image/png',
          },
          {
            src: '/icon-512.png',
            sizes: '512x512',
            type: 'image/png',
          },
        ],
      },
    }),
  ],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:4000',
        changeOrigin: true,
      },
    },
  },
  build: {
    target: 'esnext',
    minify: 'terser',
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'ui-vendor': ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
          'charts': ['recharts'],
        },
      },
    },
  },
});
```

#### 📄 `frontend/src/styles/global.css`

```css
/* Reset & Design Tokens */
:root {
  /* Colors - Dark Mode */
  --color-bg-primary: #0e1f2f;
  --color-bg-elevated: #132a3f;
  --color-bg-subtle: #17344b;
  --color-surface: #1d3d58;
  --color-accent: #00c6ff;
  --color-success: #3ddc97;
  --color-danger: #ff6b6b;
  --color-warning: #ffd166;
  --color-text-primary: #f8f9fa;
  --color-text-secondary: #d1d5db;
  --color-text-muted: rgba(209, 213, 219, 0.7);
  --color-border: rgba(0, 198, 255, 0.25);

  /* Typography */
  --font-family-base: 'Inter', -apple-system, system-ui, sans-serif;
  --font-family-mono: 'Fira Code', 'Courier New', monospace;
  --font-size-xs: 0.75rem;
  --font-size-sm: 0.875rem;
  --font-size-base: 1rem;
  --font-size-lg: 1.125rem;
  --font-size-xl: 1.5rem;
  --font-size-2xl: 2rem;

  /* Spacing (8px base) */
  --spacing-1: 0.25rem;
  --spacing-2: 0.5rem;
  --spacing-3: 0.75rem;
  --spacing-4: 1rem;
  --spacing-5: 1.25rem;
  --spacing-6: 1.5rem;
  --spacing-8: 2rem;
  --spacing-10: 2.5rem;
  --spacing-12: 3rem;

  /* Borders & Shadows */
  --radius-sm: 4px;
  --radius-md: 8px;
  --radius-lg: 16px;
  --radius-xl: 24px;
  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.12);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.15);
  --shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.2);
  --shadow-xl: 0 20px 50px rgba(0, 0, 0, 0.25);
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: var(--font-family-base);
  font-size: var(--font-size-base);
  color: var(--color-text-primary);
  background: var(--color-bg-primary);
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

/* ... mais estilos ... */
```

#### 📄 `frontend/src/main.tsx`

```typescript
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import './styles/global.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000, // 5 minutos
    },
  },
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);
```

#### 📄 `frontend/src/App.tsx`

```typescript
import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store/authStore';
import Login from './pages/Login';
import Register from './pages/Register';
import ProjectsList from './pages/ProjectsList';
import ProjectDashboard from './pages/ProjectDashboard';
import ChecklistEditor from './pages/ChecklistEditor';
import NotFound from './pages/NotFound';

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />

      <Route
        path="/projects"
        element={
          <PrivateRoute>
            <ProjectsList />
          </PrivateRoute>
        }
      />

      <Route
        path="/projects/:id/dashboard"
        element={
          <PrivateRoute>
            <ProjectDashboard />
          </PrivateRoute>
        }
      />

      <Route
        path="/projects/:id/checklist"
        element={
          <PrivateRoute>
            <ChecklistEditor />
          </PrivateRoute>
        }
      />

      <Route path="/" element={<Navigate to="/projects" />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

export default App;
```

---

## 🗄️ Database Schema SQL

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
  id VARCHAR(50) PRIMARY KEY,
  category_id VARCHAR(50) NOT NULL,
  section_id VARCHAR(50) NOT NULL,
  title VARCHAR(200) NOT NULL,
  description TEXT,
  guide_content JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_checklist_category ON checklist_items(category_id);

-- Tabela: item_states
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
  action VARCHAR(100) NOT NULL,
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

---

## 🐳 Docker & Infraestrutura

#### 📄 `docker-compose.yml`

```yaml
version: '3.9'

services:
  # PostgreSQL
  postgres:
    image: postgres:16-alpine
    container_name: appsec-postgres
    ports:
      - '5432:5432'
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: appsec_dashboard
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./v2/backend/database/init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U postgres']
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis
  redis:
    image: redis:7-alpine
    container_name: appsec-redis
    ports:
      - '6379:6379'
    volumes:
      - redis_data:/data
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
      interval: 10s
      timeout: 5s
      retries: 5

  # MinIO (S3-compatible)
  minio:
    image: minio/minio
    container_name: appsec-minio
    ports:
      - '9000:9000'
      - '9001:9001'
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
    volumes:
      - minio_data:/data
    healthcheck:
      test: ['CMD', 'curl', '-f', 'http://localhost:9000/minio/health/live']
      interval: 30s
      timeout: 20s
      retries: 3

  # Backend (NestJS)
  backend:
    build:
      context: ./v2/backend
      dockerfile: Dockerfile
    container_name: appsec-backend
    ports:
      - '4000:4000'
    environment:
      NODE_ENV: development
      DATABASE_HOST: postgres
      DATABASE_PORT: 5432
      DATABASE_USER: postgres
      DATABASE_PASSWORD: postgres
      DATABASE_NAME: appsec_dashboard
      REDIS_HOST: redis
      REDIS_PORT: 6379
      MINIO_ENDPOINT: minio
      MINIO_PORT: 9000
      JWT_SECRET: dev-secret-change-in-production-min-32-chars
      JWT_REFRESH_SECRET: dev-refresh-secret-change-in-production
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      minio:
        condition: service_healthy
    volumes:
      - ./v2/backend/src:/app/src
      - /app/node_modules
    command: npm run start:dev

  # Frontend (React)
  frontend:
    build:
      context: ./v2/frontend
      dockerfile: Dockerfile
    container_name: appsec-frontend
    ports:
      - '3000:3000'
    environment:
      VITE_API_URL: http://localhost:4000
    depends_on:
      - backend
    volumes:
      - ./v2/frontend/src:/app/src
      - /app/node_modules
    command: npm run dev

volumes:
  postgres_data:
  redis_data:
  minio_data:
```

---

## 🚀 Comandos de Setup

### 1. Setup Inicial

```bash
# Clonar o repositório
cd v2

# Backend
cd backend
npm install
cp .env.example .env
# Editar .env com suas configurações

# Frontend
cd ../frontend
npm install

# Voltar para raiz
cd ../..
```

### 2. Desenvolvimento com Docker

```bash
# Iniciar todos os serviços
docker-compose up -d

# Ver logs
docker-compose logs -f

# Parar serviços
docker-compose down

# Parar e remover volumes
docker-compose down -v
```

### 3. Desenvolvimento Local (sem Docker)

**Terminal 1: Backend**
```bash
cd v2/backend
npm run start:dev
```

**Terminal 2: Frontend**
```bash
cd v2/frontend
npm run dev
```

**Terminal 3: PostgreSQL (se não usar Docker)**
```bash
# Instalar PostgreSQL localmente
# Criar database
createdb appsec_dashboard

# Rodar migrations
cd v2/backend
npm run migration:run
```

### 4. Testes

```bash
# Backend - Unit tests
cd v2/backend
npm test

# Backend - E2E tests
npm run test:e2e

# Frontend - Unit tests
cd v2/frontend
npm test

# Frontend - Coverage
npm run test:cov
```

### 5. Build para Produção

```bash
# Backend
cd v2/backend
npm run build

# Frontend
cd v2/frontend
npm run build

# Resultado em dist/
```

---

## 📝 Próximos Passos

### Fase 1: Completar Backend (Prioridade Alta)

Criar os arquivos restantes conforme templates acima:

**1. Auth Module** (~10 arquivos)
- `src/auth/auth.module.ts`
- `src/auth/auth.controller.ts`
- `src/auth/auth.service.ts` ✅ (template fornecido)
- `src/auth/strategies/jwt.strategy.ts`
- `src/auth/strategies/local.strategy.ts`
- `src/auth/guards/jwt-auth.guard.ts`
- `src/auth/guards/roles.guard.ts`
- `src/auth/dto/login.dto.ts`
- `src/auth/dto/register.dto.ts`
- `src/auth/dto/refresh-token.dto.ts`

**2. Users Module** (~8 arquivos)
- `src/users/users.module.ts`
- `src/users/users.controller.ts`
- `src/users/users.service.ts`
- `src/users/entities/user.entity.ts` ✅ (template fornecido)
- `src/users/dto/create-user.dto.ts`
- `src/users/dto/update-user.dto.ts`
- `src/users/dto/filter-user.dto.ts`
- `src/users/users.service.spec.ts`

**3. Projects Module** (~10 arquivos)
- `src/projects/projects.module.ts`
- `src/projects/projects.controller.ts`
- `src/projects/projects.service.ts`
- `src/projects/entities/project.entity.ts` ✅ (template fornecido)
- `src/projects/entities/project-member.entity.ts`
- `src/projects/dto/create-project.dto.ts`
- `src/projects/dto/update-project.dto.ts`
- `src/projects/dto/filter-project.dto.ts`
- `src/projects/dto/add-member.dto.ts`
- `src/projects/projects.service.spec.ts`

**4. Checklists Module** (~8 arquivos)
- Similar aos módulos acima

**5. Evidence, Exports, Analytics Modules** (~30 arquivos)

### Fase 2: Completar Frontend (Prioridade Alta)

**1. Pages** (~6 arquivos)
- `src/pages/Login.tsx`
- `src/pages/Register.tsx`
- `src/pages/ProjectsList.tsx`
- `src/pages/ProjectDashboard.tsx`
- `src/pages/ChecklistEditor.tsx`
- `src/pages/NotFound.tsx`

**2. Components** (~30 arquivos)
- Design System (Button, Card, Modal, etc.)
- Layout (Header, Sidebar, Footer)
- Checklist (ChecklistItem, Section)
- Dashboard (Charts, Metrics)

**3. Services & Store** (~10 arquivos)
- API clients
- Zustand stores
- Custom hooks

### Fase 3: Integração & Testes

1. ✅ Conectar frontend com backend
2. ✅ Testar fluxos completos (E2E)
3. ✅ Load testing
4. ✅ Security audit

### Fase 4: Deploy

1. ✅ Configurar CI/CD (GitHub Actions)
2. ✅ Deploy em staging
3. ✅ Deploy em produção

---

## 💡 Dicas de Implementação

### Usar Generators NestJS

```bash
# Gerar módulo completo
nest g resource projects

# Gerar apenas service
nest g service users

# Gerar guard
nest g guard auth/jwt-auth
```

### Usar Componentes Prontos (React)

Para acelerar o desenvolvimento do frontend, usar bibliotecas:

- **Radix UI:** Componentes acessíveis
- **React Hook Form + Zod:** Formulários validados
- **Recharts:** Gráficos
- **date-fns:** Manipulação de datas

### Priorizar MVP

Focar primeiro em:
1. ✅ Autenticação JWT
2. ✅ CRUD de projetos
3. ✅ CRUD de items (checklist)
4. ✅ Dashboard básico

Depois adicionar:
- Exportações
- Analytics avançado
- WebSockets
- PWA

---

## 📞 Suporte

**Documentação Completa:** Ver `docs/` para:
- `REDESIGN-UX-UI.md`
- `FUNCIONALIDADES-PRIORIZADAS.md`
- `MELHORIAS-TECNICAS-ARQUITETURA.md`
- `CHECKLIST-SEGURANCA-APP.md`
- `PLANO-MIGRACAO.md`

---

**Status:** 🚧 Implementação em andamento

**Próximo:** Completar todos os arquivos conforme templates acima

**Estimated Time:** 4-6 semanas (com equipe de 5 pessoas)
