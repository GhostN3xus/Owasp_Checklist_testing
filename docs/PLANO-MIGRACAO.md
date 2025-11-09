# 🚀 Plano de Migração — v1.x → v2.0

**Versão:** 2.0.0
**Data:** 2025-11-09
**Responsável:** Time de Engenharia + Produto

---

## 📋 Índice

1. [Visão Geral da Migração](#visão-geral-da-migração)
2. [Análise de Impacto](#análise-de-impacto)
3. [Estratégia de Migração](#estratégia-de-migração)
4. [Fases da Migração](#fases-da-migração)
5. [Migração de Dados](#migração-de-dados)
6. [Plano de Rollback](#plano-de-rollback)
7. [Testing Strategy](#testing-strategy)
8. [Comunicação com Usuários](#comunicação-com-usuários)
9. [Timeline e Milestones](#timeline-e-milestones)
10. [Riscos e Mitigações](#riscos-e-mitigações)

---

## 🎯 Visão Geral da Migração

### Objetivo

Migrar o AppSec Dashboard da versão 1.x (Vanilla JS + Express + lowdb) para a versão 2.0 (React + NestJS + PostgreSQL) **sem perda de dados** e **mínimo downtime** para usuários existentes.

### Princípios da Migração

| Princípio | Descrição |
|-----------|-----------|
| **Zero Data Loss** | Todos os dados de `state.json` devem ser migrados para PostgreSQL |
| **Backward Compatibility** | Durante transição, ambas versões coexistem |
| **Incremental Rollout** | Deploy gradual (beta → staging → produção) |
| **Rollback Ready** | Possibilidade de reverter a qualquer momento |
| **User Communication** | Transparência total com usuários sobre mudanças |

---

## 📊 Análise de Impacto

### Mudanças Breaking

| Componente | v1.x | v2.0 | Impacto | Mitigação |
|------------|------|------|---------|-----------|
| **URL Base** | `/` | `/api/v2/` | Alto | Manter `/api/v1/` redirects |
| **Autenticação** | Nenhuma | JWT obrigatório | **Crítico** | Migration wizard guia criação de conta |
| **Single vs Multi-Project** | Um estado global | Múltiplos projetos | Alto | Criar "Projeto Padrão" com dados migrados |
| **Estrutura de Dados** | JSON flat | SQL normalizado | Médio | Script de migração automatizado |
| **File Storage** | Filesystem local | S3/MinIO | Médio | Upload automático de evidências |
| **Offline Mode** | LocalStorage | PWA com Service Worker | Baixo | Compatibilidade mantida |

### Estimativa de Impacto em Usuários

**Usuários Existentes (estimados):**
- Usuários ativos mensais: 50
- Projetos ativos: 120
- Total de dados: ~15 MB (state.json + uploads)

**Ações Necessárias pelos Usuários:**
1. ✅ **Obrigatório:** Criar conta (email + senha) no primeiro acesso pós-migração
2. ✅ **Obrigatório:** Re-login (JWT token)
3. ⚠️ **Opcional:** Configurar MFA (recomendado)
4. ⚠️ **Opcional:** Convidar membros do time

---

## 🛠️ Estratégia de Migração

### Abordagem: **Strangler Fig Pattern**

Migração incremental onde v2.0 gradualmente substitui v1.x, com ambas versões rodando em paralelo durante transição.

```
                  ┌─────────────────────┐
                  │   Load Balancer     │
                  │   (Nginx/Cloudflare)│
                  └──────────┬──────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
    ┌─────────┐        ┌─────────┐       ┌─────────┐
    │ v1.x    │  ←──►  │ Adapter │  ←──► │ v2.0    │
    │ (Legacy)│        │ Service │       │ (New)   │
    └─────────┘        └─────────┘       └─────────┘
         │                                      │
         ▼                                      ▼
    ┌─────────┐                           ┌─────────┐
    │state.json│                          │PostgreSQL│
    └─────────┘                           └─────────┘
```

**Fases:**
1. **Fase 1:** Deploy v2.0 em subdomínio (`beta.appsec-dashboard.com`)
2. **Fase 2:** Migrar dados de usuários voluntários (beta testers)
3. **Fase 3:** Adapter service permite acesso simultâneo a v1.x e v2.0
4. **Fase 4:** Forçar migração de todos os usuários (com wizard)
5. **Fase 5:** Descomissionar v1.x

---

## 📅 Fases da Migração

### FASE 0: Preparação (2 semanas) — Sprint -1

**Objetivos:**
- Finalizar desenvolvimento da v2.0
- Criar scripts de migração
- Setup de infraestrutura

**Tasks:**

| # | Tarefa | Responsável | Status |
|---|--------|-------------|--------|
| 0.1 | Finalizar backend NestJS | Backend Team | ⬜ |
| 0.2 | Finalizar frontend React | Frontend Team | ⬜ |
| 0.3 | Escrever script de migração de dados | Data Engineer | ⬜ |
| 0.4 | Setup PostgreSQL em staging | DevOps | ⬜ |
| 0.5 | Setup Redis para cache | DevOps | ⬜ |
| 0.6 | Setup S3/MinIO para files | DevOps | ⬜ |
| 0.7 | Configurar Nginx reverse proxy | DevOps | ⬜ |
| 0.8 | Criar documentação de migração | Tech Writer | ⬜ |
| 0.9 | Testes E2E completos em staging | QA Team | ⬜ |
| 0.10 | Security audit (OWASP ZAP) | Security Team | ⬜ |

**Entregáveis:**
- ✅ v2.0 funcionando em `staging.appsec-dashboard.com`
- ✅ Script `migrate-v1-to-v2.js` testado
- ✅ Documentação de migração publicada

---

### FASE 1: Beta Privado (3 semanas) — Sprint 1-2

**Objetivos:**
- Testar v2.0 com usuários reais
- Coletar feedback
- Identificar bugs críticos

**Rollout:**
- Deploy em `beta.appsec-dashboard.com`
- Convite para 10 usuários beta testers
- Dados migrados manualmente (script assistido)

**Tasks:**

| # | Tarefa | Prazo | Status |
|---|--------|-------|--------|
| 1.1 | Deploy v2.0 em beta.appsec-dashboard.com | Dia 1 | ⬜ |
| 1.2 | Enviar convites para beta testers | Dia 2 | ⬜ |
| 1.3 | Migrar dados de 10 usuários | Dia 3-5 | ⬜ |
| 1.4 | Sessões de onboarding (1h cada) | Semana 1 | ⬜ |
| 1.5 | Coletar feedback (surveys + calls) | Semana 2-3 | ⬜ |
| 1.6 | Fix bugs críticos | Contínuo | ⬜ |
| 1.7 | Iterar UX baseado em feedback | Semana 3 | ⬜ |

**KPIs de Sucesso:**
- [ ] 0 bugs críticos (P0)
- [ ] NPS >= 8/10
- [ ] 100% dos beta testers conseguem fazer login e acessar dados migrados
- [ ] Tempo médio de onboarding < 10 minutos

**Critérios de Go/No-Go para Fase 2:**
- ✅ Todos os bugs P0/P1 resolvidos
- ✅ NPS >= 7/10
- ✅ Aprovação do Product Owner

---

### FASE 2: Beta Público (4 semanas) — Sprint 3-4

**Objetivos:**
- Escalar para todos os usuários que desejarem migrar
- Self-service migration wizard
- Stress testing com tráfego real

**Rollout:**
- Banner na v1.x: "Nova versão disponível! [Experimentar Beta →]"
- Migration wizard self-service
- Ambas versões rodando em paralelo

**Tasks:**

| # | Tarefa | Prazo | Status |
|---|--------|-------|--------|
| 2.1 | Desenvolver migration wizard | Semana 1 | ⬜ |
| 2.2 | Banner na v1.x promovendo beta | Dia 1 | ⬜ |
| 2.3 | Email marketing para todos os usuários | Dia 3 | ⬜ |
| 2.4 | Monitorar inscrições e migrações | Contínuo | ⬜ |
| 2.5 | Suporte dedicado (chat + email) | Contínuo | ⬜ |
| 2.6 | Load testing (500 usuários simultâneos) | Semana 2 | ⬜ |
| 2.7 | Performance tuning | Semana 3 | ⬜ |
| 2.8 | Preparar plano de rollback | Semana 4 | ⬜ |

**Migration Wizard Flow:**

```
1. Usuário clica "Migrar para v2.0" na v1.x
   ↓
2. Redirecionado para beta.appsec-dashboard.com/migrate
   ↓
3. Wizard apresenta benefícios da v2.0
   ↓
4. Passo 1: Criar conta (email + senha + MFA opcional)
   ↓
5. Passo 2: Revisão de dados a migrar
   ↓
6. Passo 3: Confirmar migração
   ↓
7. Backend executa script de migração (5-10 segundos)
   ↓
8. Passo 4: "Migração concluída! ✅"
   ↓
9. Tour guiado das novas features
   ↓
10. Acesso ao dashboard v2.0
```

**KPIs de Sucesso:**
- [ ] 30%+ dos usuários migraram voluntariamente
- [ ] Tempo médio de migração < 2 minutos
- [ ] Taxa de sucesso de migração >= 98%
- [ ] 0 perda de dados reportada
- [ ] Uptime >= 99.5%

---

### FASE 3: Migração Forçada (2 semanas) — Sprint 5

**Objetivos:**
- Migrar todos os usuários restantes
- Descomissionar v1.x

**Rollout:**
- v1.x entra em "read-only mode"
- Banner: "v1.x será desativada em 14 dias. Migre agora!"
- Após 14 dias: Redirect forçado para v2.0

**Tasks:**

| # | Tarefa | Prazo | Status |
|---|--------|-------|--------|
| 3.1 | Anunciar deadline (email + banner) | Dia 1 | ⬜ |
| 3.2 | v1.x em read-only mode | Dia 1 | ⬜ |
| 3.3 | Suporte dedicado para migrações | Dia 1-14 | ⬜ |
| 3.4 | Emails de lembrete (D-7, D-3, D-1) | Contínuo | ⬜ |
| 3.5 | Migração automática de usuários inativos | Dia 14 | ⬜ |
| 3.6 | Redirect permanente v1.x → v2.0 | Dia 15 | ⬜ |
| 3.7 | Backup final de state.json | Dia 15 | ⬜ |
| 3.8 | Desativar servidor v1.x | Dia 16 | ⬜ |

**Comunicação:**

**Email D-14:**
```
Assunto: ⚠️ AppSec Dashboard v2.0 — Migração Obrigatória em 14 Dias

Olá {nome},

A nova versão do AppSec Dashboard (v2.0) está incrível! 🎉

Agora com:
✅ Múltiplos projetos
✅ Dashboard analítico
✅ Colaboração em equipe
✅ Exportações profissionais
✅ Muito mais!

**A versão antiga (v1.x) será desativada em 14 dias (25/11/2025).**

👉 Migre agora em menos de 2 minutos: https://appsec-dashboard.com/migrate

Seus dados serão transferidos automaticamente. Qualquer dúvida, responda este email!

Equipe AppSec Dashboard
```

---

### FASE 4: Estabilização (4 semanas) — Sprint 6-7

**Objetivos:**
- Monitorar estabilidade da v2.0
- Iterar com base em feedback
- Descomissionar infraestrutura v1.x

**Tasks:**

| # | Tarefa | Prazo | Status |
|---|--------|-------|--------|
| 4.1 | Monitorar métricas de performance | Contínuo | ⬜ |
| 4.2 | Coletar feedback pós-migração | Semana 1-2 | ⬜ |
| 4.3 | Implementar melhorias quick-win | Semana 2-3 | ⬜ |
| 4.4 | Deletar infraestrutura v1.x | Semana 4 | ⬜ |
| 4.5 | Atualizar documentação | Semana 4 | ⬜ |
| 4.6 | Celebrar com time! 🎉 | Semana 4 | ⬜ |

**KPIs de Sucesso:**
- [ ] 100% dos usuários migrados
- [ ] Uptime >= 99.9%
- [ ] p95 response time < 300ms
- [ ] NPS >= 8/10
- [ ] 0 data loss incidents

---

## 💾 Migração de Dados

### Estrutura de Dados Atual (v1.x)

**Arquivo:** `state.json`

```json
{
  "items": {
    "owasp-web::a01::a01-1": {
      "checked": true,
      "status": "failed",
      "notes": "BOLA detectado em /users/{id}",
      "attachments": [
        { "name": "screenshot.png", "path": "/uploads/123-screenshot.png" }
      ],
      "severity": "critical",
      "stage": "testing",
      "assignee": "Ana Silva",
      "priority": "p0",
      "evidenceNarrative": "Descr. técnica",
      "evidenceChecklist": {
        "screenshot": true,
        "logs": false,
        "payload": true,
        "impact": true
      }
    }
  },
  "meta": {
    "project": "API de Pagamentos",
    "tester": "João Pentester",
    "auditWindow": "Sprint 24/2025"
  }
}
```

### Mapeamento para PostgreSQL

```sql
-- Tabelas de destino:
users               → 1 registro (usuário criado no wizard)
projects            → 1 registro (nome = meta.project)
project_members     → 1 registro (user + project)
checklist_items     → Já existem (dados estáticos)
item_states         → N registros (um por item em items)
evidences           → N registros (um por attachment)
```

### Script de Migração

**Arquivo:** `scripts/migrate-v1-to-v2.ts`

```typescript
import * as fs from 'fs';
import { DataSource } from 'typeorm';
import { User } from '../src/users/entities/user.entity';
import { Project } from '../src/projects/entities/project.entity';
import { ItemState } from '../src/checklists/entities/item-state.entity';
import { Evidence } from '../src/evidence/entities/evidence.entity';
import * as bcrypt from 'bcrypt';

interface V1State {
  items: Record<string, any>;
  meta: {
    project: string;
    tester: string;
    auditWindow: string;
  };
}

export async function migrateUserData(
  email: string,
  password: string,
  stateJsonPath: string,
  uploadsDir: string,
  dataSource: DataSource
) {
  console.log(`🚀 Iniciando migração para ${email}...`);

  // 1. Carregar state.json
  const stateData: V1State = JSON.parse(fs.readFileSync(stateJsonPath, 'utf-8'));

  // 2. Criar usuário
  const userRepo = dataSource.getRepository(User);
  let user = await userRepo.findOne({ where: { email } });

  if (!user) {
    user = userRepo.create({
      email,
      passwordHash: await bcrypt.hash(password, 12),
      name: stateData.meta.tester || 'Usuário Migrado',
      role: 'admin'  // Usuário migrado vira admin do próprio projeto
    });
    await userRepo.save(user);
    console.log(`✅ Usuário criado: ${email}`);
  }

  // 3. Criar projeto
  const projectRepo = dataSource.getRepository(Project);
  const project = projectRepo.create({
    name: stateData.meta.project || 'Projeto Migrado (v1.x)',
    description: `Migrado da v1.x. Período: ${stateData.meta.auditWindow}`,
    status: 'active',
    createdBy: user,
    metadata: {
      migrated: true,
      migratedAt: new Date().toISOString(),
      v1_audit_window: stateData.meta.auditWindow
    }
  });
  await projectRepo.save(project);
  console.log(`✅ Projeto criado: ${project.name}`);

  // 4. Adicionar usuário como membro do projeto
  const memberRepo = dataSource.getRepository('project_members');
  await memberRepo.insert({
    projectId: project.id,
    userId: user.id,
    role: 'admin'
  });

  // 5. Migrar itens
  const itemStateRepo = dataSource.getRepository(ItemState);
  const evidenceRepo = dataSource.getRepository(Evidence);
  let migratedItems = 0;
  let migratedEvidences = 0;

  for (const [itemId, itemData] of Object.entries(stateData.items)) {
    const itemState = itemStateRepo.create({
      projectId: project.id,
      itemId,
      checked: itemData.checked || false,
      status: itemData.status || 'not_tested',
      severity: itemData.severity || 'medium',
      stage: itemData.stage || 'recon',
      priority: itemData.priority || 'p2',
      notes: itemData.notes || '',
      evidenceNarrative: itemData.evidenceNarrative || '',
      evidenceChecklist: itemData.evidenceChecklist || {},
      assigneeId: user.id  // Por padrão, atribuir ao usuário migrado
    });
    await itemStateRepo.save(itemState);
    migratedItems++;

    // 6. Migrar evidências (arquivos)
    if (itemData.attachments && itemData.attachments.length > 0) {
      for (const attachment of itemData.attachments) {
        const oldPath = `${uploadsDir}/${attachment.path}`;
        if (fs.existsSync(oldPath)) {
          // Copiar arquivo para novo storage (S3 ou MinIO)
          const fileBuffer = fs.readFileSync(oldPath);
          const newFilename = `${Date.now()}-${attachment.name}`;
          const newPath = `evidences/${project.id}/${newFilename}`;

          // Upload para S3 (ou salvar localmente temporariamente)
          // await s3.upload(newPath, fileBuffer);

          const evidence = evidenceRepo.create({
            itemStateId: itemState.id,
            filename: newFilename,
            originalName: attachment.name,
            mimeType: getMimeType(attachment.name),
            sizeBytes: fileBuffer.length,
            storagePath: newPath,
            uploadedBy: user
          });
          await evidenceRepo.save(evidence);
          migratedEvidences++;
        }
      }
    }
  }

  console.log(`✅ Migração concluída!`);
  console.log(`   - Itens migrados: ${migratedItems}`);
  console.log(`   - Evidências migradas: ${migratedEvidences}`);

  return {
    userId: user.id,
    projectId: project.id,
    stats: {
      items: migratedItems,
      evidences: migratedEvidences
    }
  };
}

function getMimeType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();
  const mimeTypes: Record<string, string> = {
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    pdf: 'application/pdf',
    txt: 'text/plain'
  };
  return mimeTypes[ext || ''] || 'application/octet-stream';
}
```

### Execução da Migração

**CLI Interativo:**

```bash
# Migração manual (admin)
npm run migrate:user -- \
  --email="ana@empresa.com" \
  --password="TempPassword123!" \
  --state-json="./backups/ana_state.json" \
  --uploads-dir="./uploads"

# Migração em lote (todos os usuários)
npm run migrate:batch -- \
  --users-csv="./migration/users.csv"
```

**CSV Format (`users.csv`):**

```csv
email,password,state_json_path,uploads_dir
ana@empresa.com,TempP@ss123,./backups/ana_state.json,./uploads/ana
joao@empresa.com,TempP@ss456,./backups/joao_state.json,./uploads/joao
```

---

## 🔄 Plano de Rollback

### Critérios de Rollback

Reverter para v1.x se:
- ❌ Taxa de erro > 5% nas APIs
- ❌ Uptime < 95% por 24h
- ❌ Perda de dados confirmada
- ❌ Bug P0 sem fix em 48h
- ❌ Decisão do Product Owner

### Procedimento de Rollback

**Tempo Estimado:** 15 minutos

```bash
# 1. Pausar tráfego para v2.0
kubectl scale deployment appsec-backend --replicas=0

# 2. Restaurar backup de state.json
cp /backups/state_$(date +%Y%m%d).json /app/state.json

# 3. Reativar v1.x
kubectl scale deployment appsec-legacy --replicas=3

# 4. Atualizar Nginx para rotear para v1.x
kubectl apply -f nginx-config-v1.yaml

# 5. Notificar usuários
curl -X POST $SLACK_WEBHOOK -d '{"text": "⚠️ Rollback para v1.x executado"}'
```

### Backup Strategy

| Frequência | O Que | Retenção | Local |
|------------|-------|----------|-------|
| Diário | PostgreSQL dump | 30 dias | S3 |
| Diário | state.json snapshot | 90 dias | S3 |
| Semanal | Uploads completos | 60 dias | S3 Glacier |
| Antes de deploy | Full system snapshot | 30 dias | S3 |

---

## 🧪 Testing Strategy

### Testes Automatizados

```bash
# 1. Testes unitários
npm run test:unit

# 2. Testes de integração
npm run test:integration

# 3. Testes E2E (Playwright)
npm run test:e2e

# 4. Testes de migração
npm run test:migration

# 5. Load testing (k6)
k6 run load-test.js
```

**Load Test Script (k6):**

```javascript
// load-test.js

import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 100 },  // Ramp-up to 100 users
    { duration: '5m', target: 100 },  // Stay at 100 users
    { duration: '2m', target: 200 },  // Ramp-up to 200 users
    { duration: '5m', target: 200 },  // Stay at 200 users
    { duration: '2m', target: 0 }     // Ramp-down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% requests < 500ms
    http_req_failed: ['rate<0.05']     // Error rate < 5%
  }
};

export default function () {
  const BASE_URL = 'https://appsec-dashboard.com';

  // Login
  let loginRes = http.post(`${BASE_URL}/api/v2/auth/login`, JSON.stringify({
    email: 'test@example.com',
    password: 'Test123!'
  }), {
    headers: { 'Content-Type': 'application/json' }
  });

  check(loginRes, {
    'login status is 200': (r) => r.status === 200
  });

  const token = loginRes.json('accessToken');

  // Get projects
  let projectsRes = http.get(`${BASE_URL}/api/v2/projects`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  check(projectsRes, {
    'projects status is 200': (r) => r.status === 200
  });

  sleep(1);
}
```

### Testes Manuais (QA Checklist)

- [ ] Criar conta nova
- [ ] Login com credenciais corretas
- [ ] Login com credenciais incorretas (deve falhar)
- [ ] Criar novo projeto
- [ ] Adicionar membro ao projeto
- [ ] Marcar item como "Failed"
- [ ] Upload de evidência (PNG, PDF, TXT)
- [ ] Adicionar comentário em item
- [ ] Mencionar outro usuário (@nome)
- [ ] Visualizar dashboard analítico
- [ ] Exportar relatório PDF
- [ ] Exportar Excel
- [ ] Testar filtros (status, assignee, categoria)
- [ ] Testar busca
- [ ] Logout
- [ ] Refresh token (manter sessão após 15min)
- [ ] Modo offline (PWA)
- [ ] Responsividade mobile (<768px)

---

## 📢 Comunicação com Usuários

### Canais de Comunicação

| Canal | Quando Usar | Frequência |
|-------|-------------|------------|
| **Email** | Anúncios importantes, deadlines | Semanal |
| **Banner in-app** | Promover beta, avisos | Permanente |
| **Blog Post** | Explicar features novas | A cada milestone |
| **Changelog** | Listar mudanças técnicas | A cada release |
| **Status Page** | Comunicar incidents | Real-time |
| **Slack/Discord** | Suporte direto | 24/7 |

### Templates de Comunicação

**Email: Anúncio de Beta**

```
Assunto: 🎉 Nova Versão do AppSec Dashboard (Beta)

Olá {nome},

Temos o prazer de anunciar a versão 2.0 do AppSec Dashboard!

Novidades:
🗂️ Múltiplos projetos
📊 Dashboard analítico com insights
👥 Colaboração em equipe (atribuições, comentários)
📄 Relatórios profissionais em PDF
📱 App mobile responsivo
🔒 Autenticação segura (JWT + MFA)

👉 Experimente agora: https://beta.appsec-dashboard.com

Seus dados serão migrados automaticamente. Qualquer dúvida, responda este email!

Equipe AppSec Dashboard
```

---

## 📆 Timeline e Milestones

### Gantt Chart (Resumido)

```
Sprint -1  [=== PREPARAÇÃO ===]
Sprint 1-2 [======= BETA PRIVADO =======]
Sprint 3-4 [============ BETA PÚBLICO ============]
Sprint 5   [===== MIGRAÇÃO FORÇADA =====]
Sprint 6-7 [========== ESTABILIZAÇÃO ==========]
```

### Milestones

| Data | Milestone | Critério de Sucesso |
|------|-----------|---------------------|
| 2025-11-20 | ✅ v2.0 em Staging | Todos os testes passando |
| 2025-11-25 | ✅ Beta Privado Lançado | 10 beta testers onboarded |
| 2025-12-10 | ✅ Beta Público Lançado | 30% usuários migraram |
| 2025-12-20 | ✅ Migração Forçada | 100% usuários migrados |
| 2026-01-05 | ✅ v1.x Descomissionada | Infraestrutura removida |
| 2026-01-15 | ✅ Estabilização Completa | NPS >= 8, Uptime >= 99.9% |

---

## ⚠️ Riscos e Mitigações

### Matriz de Riscos

| Risco | Probabilidade | Impacto | Mitigação |
|-------|---------------|---------|-----------|
| **Perda de dados durante migração** | Baixa | Crítico | Backups diários + testes de migração |
| **Downtime prolongado** | Média | Alto | Rollback plan + monitoring 24/7 |
| **Resistência dos usuários** | Alta | Médio | Wizard intuitivo + suporte dedicado |
| **Bugs críticos em prod** | Média | Alto | Beta testing + QA rigoroso |
| **Performance ruim (alta carga)** | Baixa | Alto | Load testing + auto-scaling |
| **Falta de recursos (time)** | Média | Médio | Buffer de 20% no timeline |
| **Incompatibilidade de dados** | Baixa | Alto | Validação de schema antes de migrar |

### Contingências

| Cenário | Ação |
|---------|------|
| Bug P0 descoberto em produção | Rollback imediato + hotfix em <24h |
| Taxa de migração baixa (<20%) | Estender prazo beta + incentivos (gamification) |
| Feedback negativo majoritário | Pause migration + iterar UX |
| Sobrecarga de servidor | Auto-scaling + otimização de queries |

---

## ✅ Checklist de Pré-Go-Live

### 48h Antes do Launch

- [ ] Todos os testes E2E passando
- [ ] Load test com 500 usuários simultâneos bem-sucedido
- [ ] Security audit (OWASP ZAP) sem vulnerabilidades críticas
- [ ] Backups automáticos configurados e testados
- [ ] Rollback plan revisado e testado
- [ ] Documentação de migração publicada
- [ ] Equipe de suporte treinada
- [ ] Monitoring/alerting configurado
- [ ] Email de comunicação rascunhado e aprovado
- [ ] Status page configurada
- [ ] Certificado SSL válido e renovação automática habilitada
- [ ] Rate limiting configurado
- [ ] CORS configurado corretamente
- [ ] Environment variables validadas (prod)
- [ ] Database connection pool configurado
- [ ] CDN configurado para assets
- [ ] Logs sendo coletados (Winston + ELK/Loki)
- [ ] Health checks configurados (Kubernetes liveness/readiness)
- [ ] Aprovação final do Product Owner

---

## 🎉 Celebração de Sucesso

### Quando 100% dos usuários estiverem migrados:

- 🍕 Pizza party para o time!
- 📧 Email de agradecimento para beta testers
- 📝 Blog post: "Case Study: Como migramos 50 usuários sem perda de dados"
- 🏆 Reconhecimento individual dos contributors
- 📊 Apresentação de métricas de sucesso para stakeholders

---

**Documento vivo** — Atualizado semanalmente durante migração.

**Responsáveis:**
- **Tech Lead:** [Nome]
- **Product Owner:** [Nome]
- **DevOps Lead:** [Nome]

**Contato de Emergência:** migration-team@appsec-dashboard.com
