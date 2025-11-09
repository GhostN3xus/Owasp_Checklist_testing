# 🔒 Checklist de Segurança — AppSec Dashboard v2.0

**Versão:** 2.0.0
**Data:** 2025-11-09
**Framework:** OWASP Top 10 2021 + ASVS 4.0

> **IRONIA ZERO:** Um aplicativo de segurança **deve ser exemplar** em suas próprias práticas de segurança.

---

## 📋 Índice

1. [A01 — Broken Access Control](#a01--broken-access-control)
2. [A02 — Cryptographic Failures](#a02--cryptographic-failures)
3. [A03 — Injection](#a03--injection)
4. [A04 — Insecure Design](#a04--insecure-design)
5. [A05 — Security Misconfiguration](#a05--security-misconfiguration)
6. [A06 — Vulnerable Components](#a06--vulnerable-components)
7. [A07 — Authentication Failures](#a07--authentication-failures)
8. [A08 — Software and Data Integrity](#a08--software-and-data-integrity)
9. [A09 — Logging and Monitoring](#a09--logging-and-monitoring)
10. [A10 — SSRF](#a10--ssrf)
11. [Infraestrutura & DevOps](#infraestrutura--devops)
12. [Checklist de Pré-Deploy](#checklist-de-pré-deploy)

---

## 🚨 A01 — Broken Access Control

### Controles de Autorização

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **1.1** | Implementar RBAC (Role-Based Access Control) | ⬜ | 3 roles: Admin, Editor, Viewer |
| **1.2** | Validar permissões em **TODOS** os endpoints | ⬜ | Middleware `RolesGuard` em NestJS |
| **1.3** | Verificar ownership de recursos | ⬜ | Usuário só acessa projetos onde é membro |
| **1.4** | Proteger contra IDOR (Insecure Direct Object References) | ⬜ | Validar `projectId` pertence ao `userId` |
| **1.5** | Deny by default | ⬜ | Sem `@Public()` decorator sem motivo explícito |
| **1.6** | Rate limiting por usuário | ⬜ | Throttle: 100 req/min por user_id |
| **1.7** | Auditoria de ações sensíveis | ⬜ | Log em `audit_logs` (criar/deletar projeto) |

**Teste de Validação:**
```bash
# Tentar acessar projeto de outro usuário
curl -H "Authorization: Bearer {user_A_token}" \
     https://api.appsec.com/api/v2/projects/{user_B_project_id}
# Esperado: 403 Forbidden
```

**Implementação (NestJS Guard):**

```typescript
// src/common/guards/project-access.guard.ts

import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { ProjectsService } from '../../projects/projects.service';

@Injectable()
export class ProjectAccessGuard implements CanActivate {
  constructor(private projectsService: ProjectsService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const userId = request.user.id;
    const projectId = request.params.id || request.body.projectId;

    if (!projectId) {
      throw new ForbiddenException('Project ID é obrigatório');
    }

    const isMember = await this.projectsService.isMember(projectId, userId);
    if (!isMember) {
      throw new ForbiddenException('Você não tem acesso a este projeto');
    }

    return true;
  }
}
```

---

## 🔐 A02 — Cryptographic Failures

### Criptografia e Proteção de Dados Sensíveis

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **2.1** | HTTPS obrigatório em produção | ⬜ | Nginx com Let's Encrypt / Cloudflare SSL |
| **2.2** | HSTS habilitado | ⬜ | `Strict-Transport-Security: max-age=31536000` |
| **2.3** | Senhas com bcrypt (cost >= 12) | ⬜ | `bcrypt.hash(password, 12)` |
| **2.4** | Tokens JWT assinados (HS256 ou RS256) | ⬜ | Secret >= 256 bits, rotacionado a cada 90 dias |
| **2.5** | Secrets em variáveis de ambiente | ⬜ | `.env` (git-ignored), AWS Secrets Manager em prod |
| **2.6** | Dados sensíveis em repouso criptografados | ⬜ | PostgreSQL com TDE (Transparent Data Encryption) |
| **2.7** | TLS 1.2+ obrigatório | ⬜ | Nginx: `ssl_protocols TLSv1.2 TLSv1.3;` |
| **2.8** | Certificados válidos e não expirados | ⬜ | Renovação automática (certbot) |
| **2.9** | Cookies com flags Secure e HttpOnly | ⬜ | `Set-Cookie: token=...; Secure; HttpOnly; SameSite=Strict` |
| **2.10** | Não logar dados sensíveis | ⬜ | Máscarar senhas, tokens, CPF em logs |

**Configuração Nginx:**

```nginx
# /etc/nginx/sites-available/appsec-dashboard

server {
  listen 443 ssl http2;
  server_name appsec-dashboard.com;

  # SSL Certificates
  ssl_certificate /etc/letsencrypt/live/appsec-dashboard.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/appsec-dashboard.com/privkey.pem;

  # SSL Configuration (A+ rating)
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers on;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;

  # HSTS
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

  # Security Headers
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-XSS-Protection "1; mode=block" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;

  # Content Security Policy
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://api.appsec-dashboard.com; frame-ancestors 'none';" always;

  location / {
    proxy_pass http://localhost:4000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_cache_bypass $http_upgrade;
  }
}

# Redirect HTTP to HTTPS
server {
  listen 80;
  server_name appsec-dashboard.com;
  return 301 https://$server_name$request_uri;
}
```

**JWT Config (NestJS):**

```typescript
// src/config/jwt.config.ts

import { JwtModuleOptions } from '@nestjs/jwt';

export const jwtConfig: JwtModuleOptions = {
  secret: process.env.JWT_SECRET,  // Min 32 chars, rotacionado a cada 90 dias
  signOptions: {
    expiresIn: '15m',  // Access token: 15 minutos
    algorithm: 'HS256',
    issuer: 'appsec-dashboard.com',
    audience: 'appsec-dashboard.com'
  }
};

// Refresh Token: Separado, TTL 7 dias
```

---

## 💉 A03 — Injection

### Proteção contra SQL, NoSQL, OS Command, XSS

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **3.1** | Usar ORM (TypeORM) com prepared statements | ⬜ | Nunca concatenar SQL manualmente |
| **3.2** | Validar tipos de entrada (DTO) | ⬜ | `class-validator` em todos os DTOs |
| **3.3** | Sanitizar HTML (anti-XSS) | ⬜ | DOMPurify no frontend, escape no backend |
| **3.4** | Escapar outputs em templates | ⬜ | React escapa por padrão, usar `dangerouslySetInnerHTML` com cuidado |
| **3.5** | Content Security Policy (CSP) | ⬜ | Ver seção A02 (Nginx config) |
| **3.6** | Não executar comandos OS com input do usuário | ⬜ | Nunca usar `child_process.exec(userInput)` |
| **3.7** | Whitelist de valores permitidos | ⬜ | Enums para status, severity, stage |
| **3.8** | Proteção contra NoSQL Injection | ⬜ | Sanitizar objetos com `express-mongo-sanitize` (se usar MongoDB) |

**Exemplo de Validação (DTO):**

```typescript
// src/projects/dto/create-project.dto.ts

import { IsString, IsArray, IsEnum, MinLength, MaxLength, IsOptional, IsUUID } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

enum ProjectStatus {
  ACTIVE = 'active',
  COMPLETED = 'completed',
  ARCHIVED = 'archived'
}

export class CreateProjectDto {
  @ApiProperty()
  @IsString()
  @MinLength(3, { message: 'Nome deve ter pelo menos 3 caracteres' })
  @MaxLength(100, { message: 'Nome deve ter no máximo 100 caracteres' })
  name: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;

  @ApiProperty()
  @IsArray()
  @IsUUID('4', { each: true, message: 'IDs de membros inválidos' })
  teamMembers: string[];

  @ApiProperty()
  @IsEnum(ProjectStatus, { message: 'Status inválido' })
  status: ProjectStatus;
}
```

**Sanitização XSS (Frontend):**

```typescript
// src/utils/sanitize.ts

import DOMPurify from 'dompurify';

export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'code', 'pre'],
    ALLOWED_ATTR: ['href', 'target'],
    ALLOW_DATA_ATTR: false
  });
}

// Uso em componente React
function CommentDisplay({ comment }: { comment: string }) {
  const cleanHtml = sanitizeHtml(comment);
  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}
```

**TypeORM Query Segura:**

```typescript
// ✅ CORRETO: Prepared statement
const projects = await this.projectsRepo.find({
  where: {
    name: Like(`%${searchTerm}%`),  // TypeORM escapa automaticamente
    status: 'active'
  }
});

// ❌ ERRADO: SQL Injection vulnerável
const projects = await this.projectsRepo.query(
  `SELECT * FROM projects WHERE name LIKE '%${searchTerm}%'`
);
```

---

## 🏗️ A04 — Insecure Design

### Design Seguro desde a Concepção

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **4.1** | Threat Modeling realizado | ⬜ | STRIDE analysis antes do desenvolvimento |
| **4.2** | Princípio do menor privilégio | ⬜ | Usuários começam como Viewer, não Admin |
| **4.3** | Defense in depth | ⬜ | Múltiplas camadas: WAF + App + DB |
| **4.4** | Secure by default | ⬜ | Configurações seguras out-of-the-box |
| **4.5** | Fail securely | ⬜ | Erros não expõem stack traces em produção |
| **4.6** | Separação de ambientes | ⬜ | Dev, Staging, Prod isolados |
| **4.7** | Limite de taxa (rate limiting) | ⬜ | Prevenir brute force e abuse |
| **4.8** | Validação de lógica de negócio | ⬜ | Ex: Não permitir auto-atribuir role Admin |

**Threat Model (STRIDE):**

| Ameaça | Exemplo | Mitigação |
|--------|---------|-----------|
| **Spoofing** | Atacante forja token JWT | JWT assinado + verificação de assinatura |
| **Tampering** | Modificar ID de projeto em request | Validar ownership no backend |
| **Repudiation** | Usuário nega ter deletado projeto | Audit logs com timestamp + user_id |
| **Information Disclosure** | Erro expõe schema do DB | Error handling customizado |
| **Denial of Service** | Flood de requests | Rate limiting + WAF |
| **Elevation of Privilege** | Viewer vira Admin | RBAC com validação estrita |

**Rate Limiting (NestJS):**

```typescript
// src/main.ts

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as helmet from 'helmet';
import * as rateLimit from 'express-rate-limit';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Helmet (security headers)
  app.use(helmet());

  // Global rate limiting
  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutos
      max: 100, // 100 requests por IP
      message: 'Muitas requisições. Tente novamente em 15 minutos.',
      standardHeaders: true,
      legacyHeaders: false
    })
  );

  await app.listen(4000);
}
bootstrap();
```

**Login Rate Limiting (Específico):**

```typescript
// src/auth/auth.controller.ts

import { Throttle } from '@nestjs/throttler';

@Controller('api/v2/auth')
export class AuthController {
  // Login: 5 tentativas a cada 15 minutos
  @Post('login')
  @Throttle(5, 900)  // 5 req / 900 segundos
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }
}
```

---

## ⚙️ A05 — Security Misconfiguration

### Configurações Seguras

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **5.1** | Remover features desnecessárias | ⬜ | Desabilitar debug mode em produção |
| **5.2** | Atualizar dependências regularmente | ⬜ | `npm audit` + Dependabot (GitHub) |
| **5.3** | Não expor versões de software | ⬜ | Remover headers `X-Powered-By` |
| **5.4** | Configurar CORS corretamente | ⬜ | Apenas origens permitidas |
| **5.5** | Desabilitar directory listing | ⬜ | Nginx `autoindex off;` |
| **5.6** | Remover arquivos de exemplo | ⬜ | `.env.example`, não `.env` |
| **5.7** | Configurar error handling | ⬜ | Não expor stack traces |
| **5.8** | Firewall configurado | ⬜ | Apenas portas 80/443 públicas |
| **5.9** | Database não exposta | ⬜ | PostgreSQL apenas em rede interna |
| **5.10** | Secrets em vault | ⬜ | AWS Secrets Manager / HashiCorp Vault |

**CORS Config (NestJS):**

```typescript
// src/main.ts

app.enableCors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://appsec-dashboard.com']  // Apenas domínio em produção
    : true,  // Qualquer origem em dev
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 3600
});
```

**Error Handling (NestJS):**

```typescript
// src/common/filters/http-exception.filter.ts

import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = exception instanceof HttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const message = exception instanceof HttpException
      ? exception.message
      : 'Internal server error';

    // Em produção, não expor stack trace
    const stack = process.env.NODE_ENV === 'production' ? undefined : (exception as Error).stack;

    response.status(status).json({
      success: false,
      error: {
        code: status,
        message,
        timestamp: new Date().toISOString(),
        path: request.url,
        ...(stack && { stack })  // Apenas em dev
      }
    });
  }
}
```

**Remover Headers Sensíveis (Nginx):**

```nginx
# Ocultar versão do Nginx
server_tokens off;

# Remover X-Powered-By (se backend envia)
proxy_hide_header X-Powered-By;
```

---

## 📦 A06 — Vulnerable and Outdated Components

### Gerenciamento de Dependências

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **6.1** | Inventário de componentes | ⬜ | `package.json` versionado |
| **6.2** | Scan de vulnerabilidades | ⬜ | `npm audit` no CI/CD |
| **6.3** | Atualizar dependências críticas | ⬜ | Patches de segurança em <48h |
| **6.4** | Remover dependências não utilizadas | ⬜ | `npm prune` |
| **6.5** | Lock de versões | ⬜ | `package-lock.json` commitado |
| **6.6** | Usar apenas pacotes confiáveis | ⬜ | Verificar downloads/semana, maintainers |
| **6.7** | SBOM (Software Bill of Materials) | ⬜ | `cyclonedx-bom` ou similar |
| **6.8** | Dependabot habilitado | ⬜ | GitHub Dependabot para PRs automáticos |

**NPM Audit no CI:**

```yaml
# .github/workflows/security-scan.yml

name: Security Scan

on:
  push:
    branches: [main, develop]
  schedule:
    - cron: '0 0 * * 1'  # Toda segunda-feira

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install dependencies
        run: npm ci
      - name: Run npm audit
        run: npm audit --audit-level=moderate
        continue-on-error: true
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
```

**Dependabot Config:**

```yaml
# .github/dependabot.yml

version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/backend"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"

  - package-ecosystem: "npm"
    directory: "/frontend"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

---

## 🔑 A07 — Identification and Authentication Failures

### Autenticação Robusta

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **7.1** | Implementar MFA (Multi-Factor Auth) | ⬜ | TOTP (Google Authenticator) opcional |
| **7.2** | Política de senhas forte | ⬜ | Min 12 chars, complexidade, sem padrões comuns |
| **7.3** | Bcrypt com cost >= 12 | ⬜ | `bcrypt.hash(password, 12)` |
| **7.4** | Proteção contra brute force | ⬜ | Rate limiting: 5 tentativas/15min |
| **7.5** | Account lockout temporário | ⬜ | Bloquear por 1h após 5 falhas |
| **7.6** | Recuperação de senha segura | ⬜ | Token único, expira em 1h, enviado por email |
| **7.7** | Session management seguro | ⬜ | JWT com refresh token, rotação periódica |
| **7.8** | Logout efetivo | ⬜ | Blacklist de tokens revogados (Redis) |
| **7.9** | Não expor erros específicos | ⬜ | "Email ou senha inválidos" (não "Email não existe") |
| **7.10** | CAPTCHA em login/register | ⬜ | Google reCAPTCHA v3 |

**Política de Senhas:**

```typescript
// src/auth/validators/password.validator.ts

import * as zxcvbn from 'zxcvbn';

export function validatePassword(password: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Tamanho mínimo
  if (password.length < 12) {
    errors.push('Senha deve ter pelo menos 12 caracteres');
  }

  // Complexidade
  if (!/[A-Z]/.test(password)) {
    errors.push('Senha deve conter pelo menos uma letra maiúscula');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Senha deve conter pelo menos uma letra minúscula');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Senha deve conter pelo menos um número');
  }
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Senha deve conter pelo menos um caractere especial');
  }

  // Força da senha (usando zxcvbn)
  const strength = zxcvbn(password);
  if (strength.score < 3) {
    errors.push('Senha é fraca. Use palavras menos comuns e adicione números/símbolos.');
  }

  // Senhas comuns (blacklist)
  const commonPasswords = ['password123', '12345678', 'admin123', 'letmein'];
  if (commonPasswords.includes(password.toLowerCase())) {
    errors.push('Senha é muito comum. Escolha outra.');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
```

**Brute Force Protection:**

```typescript
// src/auth/guards/brute-force.guard.ts

import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import Redis from 'ioredis';

@Injectable()
export class BruteForceGuard implements CanActivate {
  constructor(@InjectRedis() private redis: Redis) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const ip = request.ip;
    const email = request.body.email;

    const key = `login_attempts:${email}:${ip}`;
    const attempts = await this.redis.get(key);

    if (attempts && parseInt(attempts) >= 5) {
      const ttl = await this.redis.ttl(key);
      throw new HttpException(
        `Muitas tentativas de login. Tente novamente em ${Math.ceil(ttl / 60)} minutos.`,
        HttpStatus.TOO_MANY_REQUESTS
      );
    }

    return true;
  }
}

// No serviço de autenticação, incrementar contador
async recordFailedLogin(email: string, ip: string) {
  const key = `login_attempts:${email}:${ip}`;
  await this.redis.incr(key);
  await this.redis.expire(key, 900);  // 15 minutos
}
```

**JWT com Refresh Token:**

```typescript
// src/auth/auth.service.ts

async login(email: string, password: string) {
  const user = await this.usersService.findByEmail(email);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    throw new UnauthorizedException('Email ou senha inválidos');
  }

  // Access token (curto)
  const accessToken = this.jwtService.sign(
    { sub: user.id, email: user.email, role: user.role },
    { expiresIn: '15m' }
  );

  // Refresh token (longo)
  const refreshToken = this.jwtService.sign(
    { sub: user.id, type: 'refresh' },
    { expiresIn: '7d', secret: process.env.JWT_REFRESH_SECRET }
  );

  // Salvar refresh token no Redis (associado ao usuário)
  await this.redis.set(
    `refresh_token:${user.id}`,
    refreshToken,
    'EX',
    7 * 24 * 60 * 60  // 7 dias
  );

  return { accessToken, refreshToken, user };
}

async refreshAccessToken(refreshToken: string) {
  try {
    const payload = this.jwtService.verify(refreshToken, {
      secret: process.env.JWT_REFRESH_SECRET
    });

    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('Token inválido');
    }

    // Verificar se refresh token ainda é válido no Redis
    const storedToken = await this.redis.get(`refresh_token:${payload.sub}`);
    if (storedToken !== refreshToken) {
      throw new UnauthorizedException('Refresh token revogado');
    }

    // Gerar novo access token
    const user = await this.usersService.findById(payload.sub);
    const accessToken = this.jwtService.sign(
      { sub: user.id, email: user.email, role: user.role },
      { expiresIn: '15m' }
    );

    return { accessToken };
  } catch (error) {
    throw new UnauthorizedException('Refresh token inválido ou expirado');
  }
}

async logout(userId: string) {
  // Remover refresh token do Redis
  await this.redis.del(`refresh_token:${userId}`);
}
```

---

## 🔗 A08 — Software and Data Integrity Failures

### Integridade de Software e Dados

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **8.1** | CI/CD pipeline com verificações | ⬜ | Testes + linter + security scan |
| **8.2** | Code signing (opcional) | ⬜ | Assinar releases com GPG |
| **8.3** | SRI (Subresource Integrity) para CDNs | ⬜ | `<script integrity="sha384-...">` |
| **8.4** | Verificar integridade de downloads | ⬜ | Checksum de arquivos exportados |
| **8.5** | Proteção contra desserialização insegura | ⬜ | Validar JSON antes de parse |
| **8.6** | Versionamento de schema de dados | ⬜ | Migrations do TypeORM |
| **8.7** | Backup automático | ⬜ | PostgreSQL backup diário |
| **8.8** | Auditoria de mudanças críticas | ⬜ | Trigger `audit_logs` no DB |

**SRI para CDNs:**

```html
<!-- index.html -->
<link
  rel="stylesheet"
  href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
  integrity="sha384-..."
  crossorigin="anonymous"
/>
```

**Migrations Versionadas (TypeORM):**

```bash
# Criar migration
npm run typeorm migration:generate -- -n AddRoleToUsers

# Aplicar migrations
npm run typeorm migration:run

# Reverter migration
npm run typeorm migration:revert
```

```typescript
// migrations/1699999999999-AddRoleToUsers.ts

import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddRoleToUsers1699999999999 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'role',
        type: 'enum',
        enum: ['admin', 'editor', 'viewer'],
        default: "'editor'",
        isNullable: false
      })
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('users', 'role');
  }
}
```

**Backup Automático (PostgreSQL):**

```bash
# Cron job para backup diário
0 2 * * * pg_dump -U postgres appsec_dashboard | gzip > /backups/appsec_$(date +\%Y\%m\%d).sql.gz

# Rotação de backups (manter últimos 30 dias)
0 3 * * * find /backups -name "appsec_*.sql.gz" -mtime +30 -delete
```

---

## 📊 A09 — Security Logging and Monitoring Failures

### Logging e Monitoramento

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **9.1** | Logging centralizado | ⬜ | Winston + Elasticsearch/Loki |
| **9.2** | Logar eventos de segurança | ⬜ | Login, logout, falhas auth, mudanças de permissões |
| **9.3** | Logar ações sensíveis | ⬜ | Criar/deletar projeto, mudar role |
| **9.4** | Timestamp em todos os logs | ⬜ | ISO 8601 format |
| **9.5** | Correlação de logs (request ID) | ⬜ | UUID em cada request |
| **9.6** | Não logar dados sensíveis | ⬜ | Máscarar senhas, tokens, PII |
| **9.7** | Alertas em eventos críticos | ⬜ | Email/Slack em múltiplas falhas de login |
| **9.8** | Monitoramento de uptime | ⬜ | UptimeRobot, StatusCake |
| **9.9** | APM (Application Performance Monitoring) | ⬜ | New Relic, DataDog |
| **9.10** | Retenção de logs | ⬜ | 90 dias mínimo |

**Winston Logger (NestJS):**

```typescript
// src/common/logger/winston.config.ts

import * as winston from 'winston';
import { WinstonModule } from 'nest-winston';

export const winstonConfig = WinstonModule.createLogger({
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, context, requestId, ...meta }) => {
          return `${timestamp} [${level}] [${context || 'App'}] [${requestId || 'N/A'}]: ${message} ${
            Object.keys(meta).length ? JSON.stringify(meta) : ''
          }`;
        })
      )
    }),
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    }),
    new winston.transports.File({
      filename: 'logs/combined.log',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      )
    })
  ]
});
```

**Logging Interceptor:**

```typescript
// src/common/interceptors/logging.interceptor.ts

import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('HTTP');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url, body, user } = request;
    const requestId = uuidv4();
    request.requestId = requestId;

    const now = Date.now();
    this.logger.log({
      message: 'Incoming request',
      requestId,
      method,
      url,
      userId: user?.id,
      body: this.sanitizeBody(body)
    });

    return next.handle().pipe(
      tap(() => {
        const response = context.switchToHttp().getResponse();
        const { statusCode } = response;
        const responseTime = Date.now() - now;

        this.logger.log({
          message: 'Outgoing response',
          requestId,
          method,
          url,
          statusCode,
          responseTime: `${responseTime}ms`
        });
      })
    );
  }

  private sanitizeBody(body: any) {
    if (!body) return undefined;
    const sanitized = { ...body };
    ['password', 'token', 'secret'].forEach(key => {
      if (sanitized[key]) sanitized[key] = '***REDACTED***';
    });
    return sanitized;
  }
}
```

**Alertas de Segurança:**

```typescript
// src/common/services/alerting.service.ts

import { Injectable, Logger } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import Redis from 'ioredis';
// import * as nodemailer from 'nodemailer';  // Email
// import axios from 'axios';  // Slack webhook

@Injectable()
export class AlertingService {
  private readonly logger = new Logger(AlertingService.name);

  constructor(@InjectRedis() private redis: Redis) {}

  async alertMultipleFailedLogins(email: string, count: number, ip: string) {
    const key = `alert_sent:failed_login:${email}`;
    const alreadySent = await this.redis.get(key);

    if (!alreadySent) {
      this.logger.warn(`⚠️ ALERTA: ${count} tentativas de login falhadas para ${email} do IP ${ip}`);

      // Enviar email para admin
      // await this.sendEmail(...);

      // Enviar para Slack
      // await axios.post(process.env.SLACK_WEBHOOK_URL, { text: `...` });

      // Evitar spam: Apenas 1 alerta a cada 1 hora
      await this.redis.set(key, '1', 'EX', 3600);
    }
  }
}
```

---

## 🌐 A10 — Server-Side Request Forgery (SSRF)

### Proteção contra SSRF

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **10.1** | Validar URLs fornecidas por usuários | ⬜ | Whitelist de domínios permitidos |
| **10.2** | Não permitir acesso a IPs privados | ⬜ | Bloquear 127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16 |
| **10.3** | Usar proxy para requests externos | ⬜ | Proxy que filtra destinos |
| **10.4** | Timeout curto em HTTP requests | ⬜ | Max 5 segundos |
| **10.5** | Desabilitar redirects automáticos | ⬜ | `axios.get(url, { maxRedirects: 0 })` |

**SSRF Protection:**

```typescript
// src/common/validators/url.validator.ts

import { URL } from 'url';

const PRIVATE_IP_RANGES = [
  /^127\./,         // Localhost
  /^10\./,          // Private Class A
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private Class B
  /^192\.168\./,    // Private Class C
  /^169\.254\./,    // Link-local
  /^::1$/,          // IPv6 localhost
  /^fc00:/,         // IPv6 unique local
  /^fe80:/          // IPv6 link-local
];

export function isUrlSafe(urlString: string): boolean {
  try {
    const url = new URL(urlString);

    // Apenas HTTP/HTTPS
    if (!['http:', 'https:'].includes(url.protocol)) {
      return false;
    }

    // Bloquear IPs privados
    const hostname = url.hostname;
    for (const range of PRIVATE_IP_RANGES) {
      if (range.test(hostname)) {
        return false;
      }
    }

    // Whitelist de domínios (opcional)
    const allowedDomains = ['owasp.org', 'cwe.mitre.org'];
    const isWhitelisted = allowedDomains.some(domain => hostname.endsWith(domain));
    if (!isWhitelisted) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
}

// Uso em serviço
async fetchExternalUrl(url: string) {
  if (!isUrlSafe(url)) {
    throw new BadRequestException('URL não permitida');
  }

  const response = await axios.get(url, {
    timeout: 5000,
    maxRedirects: 0,
    validateStatus: (status) => status < 400
  });

  return response.data;
}
```

---

## 🏗️ Infraestrutura & DevOps

### Hardening de Infraestrutura

| # | Controle | Status | Implementação |
|---|----------|--------|---------------|
| **11.1** | Firewall configurado | ⬜ | UFW/iptables: Apenas 80/443 públicos |
| **11.2** | SSH desabilitado (ou apenas key-based) | ⬜ | `PasswordAuthentication no` |
| **11.3** | Fail2Ban habilitado | ⬜ | Ban IPs após 5 tentativas SSH |
| **11.4** | Updates automáticos de segurança | ⬜ | `unattended-upgrades` |
| **11.5** | Docker containers non-root | ⬜ | `USER node` no Dockerfile |
| **11.6** | Secrets em vault | ⬜ | AWS Secrets Manager / Vault |
| **11.7** | Network segmentation | ⬜ | DB em rede privada, não pública |
| **11.8** | DDoS protection | ⬜ | Cloudflare / AWS Shield |
| **11.9** | WAF (Web Application Firewall) | ⬜ | Cloudflare WAF / ModSecurity |
| **11.10** | Backups testados | ⬜ | Restore test mensal |

**Dockerfile Seguro:**

```dockerfile
# backend/Dockerfile

FROM node:20-alpine AS builder

# Criar user não-root
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

WORKDIR /app

# Copiar apenas package.json primeiro (cache layer)
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copiar código
COPY . .
RUN npm run build

# ────────────────────────────────────────
# Production image
FROM node:20-alpine

RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

WORKDIR /app

# Copiar node_modules e build do builder
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

# Não rodar como root
USER nodejs

EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); })"

CMD ["node", "dist/main.js"]
```

---

## ✅ Checklist de Pré-Deploy

### Antes de fazer deploy em produção, verificar:

#### Código

- [ ] Sem senhas/secrets hardcoded no código
- [ ] Variáveis de ambiente configuradas (`.env` não commitado)
- [ ] Debug mode desabilitado (`NODE_ENV=production`)
- [ ] Source maps desabilitados em produção
- [ ] Console.logs removidos ou configurados para produção

#### Testes

- [ ] Testes unitários passando (cobertura >= 80%)
- [ ] Testes de integração passando
- [ ] Testes E2E passando
- [ ] Scan de vulnerabilidades (`npm audit`, Snyk)
- [ ] OWASP ZAP / Burp Suite scan realizado

#### Segurança

- [ ] HTTPS configurado (certificado SSL válido)
- [ ] HSTS habilitado
- [ ] CSP configurado
- [ ] CORS configurado corretamente
- [ ] Rate limiting habilitado
- [ ] JWT secrets fortes e rotacionados
- [ ] Bcrypt cost >= 12
- [ ] Database não exposto publicamente
- [ ] Firewall configurado (apenas 80/443)
- [ ] Secrets em vault (AWS/Vault)

#### Infraestrutura

- [ ] Backup automático configurado
- [ ] Monitoring/alerting configurado
- [ ] Logging centralizado (Winston + ELK/Loki)
- [ ] CDN configurado para assets
- [ ] Redis cache configurado
- [ ] Database connection pool configurado
- [ ] Health checks configurados
- [ ] Rollback plan documentado

#### Performance

- [ ] Bundle JS < 300 KB (gzipped)
- [ ] Imagens otimizadas (WebP, lazy loading)
- [ ] Code splitting configurado
- [ ] Lighthouse score >= 90
- [ ] Load testing realizado (k6, JMeter)

#### Compliance

- [ ] LGPD/GDPR compliance (se aplicável)
- [ ] Política de privacidade publicada
- [ ] Termos de uso publicados
- [ ] Cookie consent implementado

---

## 📞 Contato

**Security Team:** security@appsec-dashboard.com

**Bug Bounty:** https://appsec-dashboard.com/security/bug-bounty

**Responsible Disclosure:** Reportar vulnerabilidades via security@appsec-dashboard.com (PGP key disponível)

---

**Documento vivo** — Atualizado a cada release de segurança.
