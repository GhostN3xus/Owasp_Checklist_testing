# 🎯 Funcionalidades Priorizadas — AppSec Dashboard v2.0

**Versão:** 2.0.0
**Data:** 2025-11-09
**Framework:** Moscow Prioritization + User Story Mapping

---

## 📋 Índice

1. [Metodologia de Priorização](#metodologia-de-priorização)
2. [Épicos & User Stories](#épicos--user-stories)
3. [Roadmap de Releases](#roadmap-de-releases)
4. [Matriz de Esforço vs Valor](#matriz-de-esforço-vs-valor)

---

## 🎯 Metodologia de Priorização

### Framework: MoSCoW

| Categoria | Descrição | % do Backlog |
|-----------|-----------|--------------|
| **Must Have** | Funcionalidades críticas para MVP | 40% |
| **Should Have** | Importantes mas não bloqueantes | 30% |
| **Could Have** | Desejáveis se houver tempo | 20% |
| **Won't Have** | Fora do escopo desta release | 10% |

### Critérios de Priorização

```
Score = (Valor para Usuário × 3) + (Viabilidade Técnica × 2) + (Alinhamento Estratégico × 1.5) − (Complexidade × 2)
```

| Feature | Valor | Viab. | Align. | Complex. | **Score** |
|---------|-------|-------|--------|----------|-----------|
| Gerenciamento de Projetos | 10 | 8 | 10 | 5 | **38** ⭐ |
| Dashboard Analítico | 9 | 7 | 9 | 6 | **32** ⭐ |
| Exportação PDF Pro | 10 | 6 | 8 | 7 | **30** ⭐ |
| Autenticação JWT | 10 | 9 | 10 | 4 | **41** ⭐⭐ |
| Colaboração Multi-User | 8 | 5 | 8 | 8 | **19** |
| i18n (Multi-idioma) | 5 | 7 | 6 | 6 | **11** |
| Mobile App Nativo | 7 | 3 | 6 | 10 | **0** ❌ |

---

## 📚 Épicos & User Stories

### ÉPICO 1: Gerenciamento de Projetos (MUST HAVE) ⭐

**Objetivo:** Permitir que usuários organizem auditorias em projetos isolados.

**Valor de Negócio:** Alto — Organizações testam múltiplas aplicações simultaneamente.

**Estimativa:** 13 Story Points (Sprint 1)

---

#### 🎫 US-101: Criar Novo Projeto

**Como** analista de segurança,
**Quero** criar um novo projeto de auditoria,
**Para que** eu possa organizar checklists por aplicação testada.

**Critérios de Aceitação:**
- [ ] Botão "Novo Projeto" visível na landing page
- [ ] Modal abre com campos: Nome, Descrição, Team Members, Categorias (multi-select)
- [ ] Validação: Nome obrigatório (3-100 chars)
- [ ] Ao salvar, projeto aparece na lista de projetos
- [ ] Projeto recebe UUID único
- [ ] Estado inicial: 0% completado, status "Em andamento"

**Testes:**
```gherkin
Scenario: Criar projeto com sucesso
  Given estou na página "Projetos"
  When clico em "Novo Projeto"
  And preencho Nome: "API de Pagamentos v2.1"
  And seleciono categorias: ["OWASP Web", "OWASP API"]
  And clico em "Criar"
  Then vejo toast "Projeto criado com sucesso"
  And sou redirecionado para "/projetos/{id}/dashboard"
  And projeto aparece na lista com status "Em andamento"
```

**Mockup:**
```
┌─────────────────────────────────────────┐
│  Criar Novo Projeto              [✖]    │
├─────────────────────────────────────────┤
│                                         │
│  Nome *                                 │
│  [API de Pagamentos v2.1___________]    │
│                                         │
│  Descrição (opcional)                   │
│  [Teste de segurança pré-produção__]    │
│                                         │
│  Team Members                           │
│  [Ana Silva, João Pentester_____] [+]   │
│                                         │
│  Categorias *                           │
│  ☑️ OWASP Web                           │
│  ☑️ OWASP API Security                  │
│  ☐ Mobile Security (MASVS)              │
│  ☐ Cloud Security                       │
│                                         │
│  [Cancelar]  [Criar Projeto]            │
└─────────────────────────────────────────┘
```

**Endpoint API:**
```http
POST /api/v2/projects
Content-Type: application/json
Authorization: Bearer {jwt}

{
  "name": "API de Pagamentos v2.1",
  "description": "Teste de segurança pré-produção",
  "teamMembers": ["user-123", "user-456"],
  "categories": ["owasp-web", "api-security"],
  "metadata": {
    "client": "Empresa X",
    "deadline": "2025-12-31"
  }
}

Response 201 Created:
{
  "id": "proj_abc123xyz",
  "name": "API de Pagamentos v2.1",
  "status": "active",
  "progress": 0,
  "createdAt": "2025-11-09T10:30:00Z",
  "createdBy": "user-123"
}
```

---

#### 🎫 US-102: Listar e Filtrar Projetos

**Como** gerente de segurança,
**Quero** visualizar todos os projetos da organização com filtros,
**Para que** eu possa acompanhar múltiplas auditorias simultaneamente.

**Critérios de Aceitação:**
- [ ] Landing page mostra grid/lista de projetos
- [ ] Card de projeto exibe: Nome, Status, Progress %, Team, Última atualização
- [ ] Filtros disponíveis: Status (Ativo/Concluído/Arquivado), Responsável, Data
- [ ] Busca por nome (debounced, 300ms)
- [ ] Ordenação: Mais recentes, Nome A-Z, Progress %
- [ ] Paginação: 10 projetos por página
- [ ] Skeleton loading durante fetch

**Endpoint API:**
```http
GET /api/v2/projects?status=active&page=1&limit=10&sort=updatedAt:desc
Authorization: Bearer {jwt}

Response 200 OK:
{
  "projects": [
    {
      "id": "proj_123",
      "name": "API de Pagamentos v2.1",
      "status": "active",
      "progress": 65,
      "teamMembers": ["Ana Silva", "João Pentester"],
      "riskScore": 7.8,
      "updatedAt": "2025-11-09T08:00:00Z"
    }
  ],
  "pagination": {
    "total": 45,
    "page": 1,
    "pages": 5
  }
}
```

---

#### 🎫 US-103: Arquivar e Deletar Projeto

**Como** administrador,
**Quero** arquivar ou deletar projetos antigos,
**Para que** a lista fique organizada e sem poluição.

**Critérios de Aceitação:**
- [ ] Botão "Arquivar" no menu de ações do projeto
- [ ] Confirmação: "Tem certeza? Projeto ficará somente-leitura"
- [ ] Projetos arquivados não aparecem na lista padrão (filtro separado)
- [ ] Botão "Deletar" disponível apenas para admins
- [ ] Confirmação com digitação do nome do projeto
- [ ] Soft delete: dados não são apagados imediatamente (retention de 30 dias)

**Endpoint API:**
```http
PATCH /api/v2/projects/{id}/archive
Authorization: Bearer {jwt}

Response 200 OK:
{ "status": "archived" }

DELETE /api/v2/projects/{id}
Authorization: Bearer {jwt}
X-Confirm: {project_name}

Response 202 Accepted:
{ "message": "Projeto agendado para exclusão em 30 dias" }
```

---

### ÉPICO 2: Dashboard Analítico (MUST HAVE) ⭐

**Objetivo:** Fornecer visão gerencial do progresso e riscos da auditoria.

**Valor de Negócio:** Alto — C-level e gerentes precisam de métricas sem entrar nos checklists.

**Estimativa:** 21 Story Points (Sprint 2)

---

#### 🎫 US-201: Métricas Gerais

**Como** gerente de segurança,
**Quero** visualizar métricas consolidadas do projeto,
**Para que** eu possa reportar progresso rapidamente.

**Critérios de Aceitação:**
- [ ] Dashboard mostra 6-8 cards de métricas:
  - Total de itens mapeados
  - Itens concluídos (%)
  - Itens com falha (críticos destacados)
  - Itens N/A
  - Itens pendentes
  - Total de evidências anexadas
  - Tempo médio por item
  - Número de colaboradores ativos
- [ ] Cards com animação de contagem (count-up)
- [ ] Atualização em tempo real (WebSocket ou polling 30s)
- [ ] Ícones intuitivos e cores semânticas

**Endpoint API:**
```http
GET /api/v2/projects/{id}/metrics
Authorization: Bearer {jwt}

Response 200 OK:
{
  "total": 300,
  "completed": 195,
  "passed": 145,
  "failed": 54,
  "na": 23,
  "pending": 78,
  "evidences": 132,
  "avgTimePerItem": 420,  // segundos
  "activeCollaborators": 3
}
```

---

#### 🎫 US-202: Gráfico de Cobertura por Categoria

**Como** analista de segurança,
**Quero** visualizar um gráfico radial/donut da cobertura por categoria,
**Para que** eu identifique gaps rapidamente.

**Critérios de Aceitação:**
- [ ] Gráfico tipo radar/radial com % de conclusão por categoria
- [ ] Categorias: OWASP Web, API, Mobile, Cloud, etc.
- [ ] Hover mostra tooltip: "OWASP Web: 24/30 itens (80%)"
- [ ] Clique na fatia filtra checklist para aquela categoria
- [ ] Legenda com cores distintas
- [ ] Responsivo (reduz em mobile)

**Biblioteca Sugerida:** Chart.js ou Recharts (React)

---

#### 🎫 US-203: Top Riscos Críticos

**Como** CISO,
**Quero** ver uma lista rankeada dos 5-10 riscos mais críticos,
**Para que** eu priorize remediações.

**Critérios de Aceitação:**
- [ ] Lista ordenada por severidade (Critical > High > Medium)
- [ ] Cada item mostra:
  - Título da vulnerabilidade
  - Categoria (A01, API1, etc.)
  - Severidade (badge colorido)
  - Assignee
  - Número de evidências
  - Status de mitigação
- [ ] Clique no item abre modal com detalhes completos
- [ ] Badge "NEW" para riscos adicionados nas últimas 24h
- [ ] Filtro: Mostrar apenas "Não mitigados"

**Endpoint API:**
```http
GET /api/v2/projects/{id}/top-risks?limit=5
Authorization: Bearer {jwt}

Response 200 OK:
{
  "risks": [
    {
      "id": "item_abc",
      "title": "BOLA em /users/{id}",
      "category": "A01",
      "severity": "critical",
      "assignee": "Ana Silva",
      "evidences": 3,
      "mitigationStatus": "pending",
      "discoveredAt": "2025-11-08T14:00:00Z"
    }
  ]
}
```

---

#### 🎫 US-204: Timeline de Workflow

**Como** lead de segurança,
**Quero** visualizar o progresso por fase do workflow,
**Para que** eu saiba em que etapa a equipe está focada.

**Critérios de Aceitação:**
- [ ] 5 fases: Recon, Testing, Access Control, Report, Mitigate
- [ ] Cada fase mostra progress bar horizontal com %
- [ ] Tooltip: "Testing: 65% (195/300 itens nesta fase)"
- [ ] Cores diferentes por fase (gradiente de azul)
- [ ] Clique na fase filtra checklist para aquela etapa

---

#### 🎫 US-205: Feed de Atividade Recente

**Como** membro do time,
**Quero** ver um feed das últimas ações da equipe,
**Para que** eu acompanhe o trabalho dos colegas.

**Critérios de Aceitação:**
- [ ] Feed reverso (mais recente no topo)
- [ ] Últimas 20 ações, com "Ver mais"
- [ ] Formato: "{Nome} {ação} {item} há {tempo}"
  - Ex: "Ana marcou A01-5 como Failed há 2 horas"
- [ ] Ícones por tipo de ação: ✓ Check, ✗ Failed, 📎 Upload, 📝 Nota
- [ ] Link clicável para o item mencionado
- [ ] Auto-refresh a cada 30s

**Endpoint API:**
```http
GET /api/v2/projects/{id}/activity?limit=20
Authorization: Bearer {jwt}

Response 200 OK:
{
  "activities": [
    {
      "id": "act_123",
      "type": "status_change",
      "user": "Ana Silva",
      "item": "A01-5",
      "itemTitle": "Revisar IDOR",
      "action": "marcou como Failed",
      "timestamp": "2025-11-09T08:30:00Z"
    }
  ]
}
```

---

### ÉPICO 3: Colaboração Multi-User (SHOULD HAVE) 🟡

**Objetivo:** Permitir múltiplos analistas trabalharem simultaneamente no mesmo projeto.

**Valor de Negócio:** Médio-Alto — Essencial para empresas com equipes de AppSec.

**Estimativa:** 34 Story Points (Sprint 3-4)

---

#### 🎫 US-301: Atribuição de Itens

**Como** lead de segurança,
**Quero** atribuir itens específicos para membros da equipe,
**Para que** o trabalho seja distribuído claramente.

**Critérios de Aceitação:**
- [ ] Campo "Assignee" em cada item de checklist
- [ ] Dropdown com autocomplete dos membros do projeto
- [ ] Possibilidade de atribuir múltiplos assignees (co-ownership)
- [ ] Badge visual no item: "Atribuído a: Ana"
- [ ] Filtro: "Meus itens" mostra apenas itens do usuário logado
- [ ] Notificação ao assignee quando item for atribuído (in-app ou email)

---

#### 🎫 US-302: Comentários e Discussões

**Como** analista de segurança,
**Quero** comentar em itens específicos do checklist,
**Para que** eu possa discutir achados com a equipe.

**Critérios de Aceitação:**
- [ ] Botão "Comentários (N)" em cada item
- [ ] Thread de comentários com timestamp e autor
- [ ] Suporte a Markdown básico (negrito, itálico, código)
- [ ] Menções: @nome notifica o usuário
- [ ] Notificações in-app quando mencionado
- [ ] Possibilidade de resolver/fechar thread

**Endpoint API:**
```http
POST /api/v2/items/{id}/comments
Authorization: Bearer {jwt}
Content-Type: application/json

{
  "text": "Confirmado BOLA. @joao pode revisar a evidência?",
  "mentions": ["user-456"]
}

Response 201 Created:
{
  "id": "comment_abc",
  "author": "Ana Silva",
  "text": "Confirmado BOLA. @joao pode revisar a evidência?",
  "createdAt": "2025-11-09T10:00:00Z"
}
```

---

#### 🎫 US-303: Permissões por Função (RBAC)

**Como** administrador da organização,
**Quero** definir permissões por função (Admin, Editor, Viewer),
**Para que** auditores externos tenham acesso limitado.

**Critérios de Aceitação:**
- [ ] 3 roles padrão:
  - **Admin:** Criar/deletar projetos, gerenciar usuários, exportar
  - **Editor:** Editar checklists, adicionar evidências, comentar
  - **Viewer:** Somente leitura (visualizar checklists e relatórios)
- [ ] Interface de gerenciamento de membros no projeto
- [ ] Convite por email com role específico
- [ ] Auditoria de permissões (log de quem mudou o quê)

**Tabela de Permissões:**

| Ação | Admin | Editor | Viewer |
|------|-------|--------|--------|
| Criar projeto | ✅ | ❌ | ❌ |
| Editar checklist | ✅ | ✅ | ❌ |
| Visualizar dados | ✅ | ✅ | ✅ |
| Exportar relatório | ✅ | ✅ | ✅ |
| Deletar projeto | ✅ | ❌ | ❌ |
| Convidar membros | ✅ | ❌ | ❌ |

---

#### 🎫 US-304: Real-Time Collaboration (WebSockets)

**Como** analista de segurança,
**Quero** ver quando colegas estão editando o mesmo item,
**Para que** evitemos conflitos de edição.

**Critérios de Aceitação:**
- [ ] Avatar do usuário aparece no item sendo editado
- [ ] Toast: "João está editando este item"
- [ ] Lock otimista: Último a salvar vence (com aviso)
- [ ] Indicador "Online" na lista de membros do projeto
- [ ] Cursor multi-user (opcional, nice-to-have)

**Tecnologia:** Socket.io ou WebSockets nativo

---

### ÉPICO 4: Exportações Profissionais (MUST HAVE) ⭐

**Objetivo:** Gerar relatórios customizáveis em múltiplos formatos.

**Valor de Negócio:** Crítico — Entregável final para clientes e stakeholders.

**Estimativa:** 21 Story Points (Sprint 2-3)

---

#### 🎫 US-401: Exportação PDF com Templates

**Como** consultor de segurança,
**Quero** gerar relatórios PDF com templates customizáveis,
**Para que** eu entregue documentos profissionais para clientes.

**Critérios de Aceitação:**
- [ ] 4 templates pré-definidos:
  - **Executivo:** Capa, sumário, gráficos, top 10 riscos (15-20 páginas)
  - **Técnico:** Todos os itens failed + payloads + referências (50+ páginas)
  - **Compliance:** Mapeamento para frameworks (PCI-DSS, ISO 27001, SOC 2)
  - **Quick Summary:** 1-2 páginas com métricas principais
- [ ] Opções de customização:
  - Logo da empresa (upload)
  - Cores do tema
  - Incluir/excluir seções
  - Filtros (apenas failed, apenas critical, etc.)
- [ ] Preview antes de gerar (primeira página)
- [ ] Geração assíncrona com progress bar
- [ ] Download automático ao finalizar
- [ ] Armazenamento de histórico de relatórios gerados

**Stack Técnico:**
- **Backend:** Puppeteer (headless Chrome) ou pdfkit
- **Frontend:** React-PDF para preview

**Endpoint API:**
```http
POST /api/v2/projects/{id}/export/pdf
Authorization: Bearer {jwt}
Content-Type: application/json

{
  "template": "technical",
  "options": {
    "includeCover": true,
    "includeSummary": true,
    "includeEvidence": true,
    "filters": {
      "status": ["failed"],
      "severity": ["critical", "high"]
    },
    "language": "pt-BR",
    "logo": "data:image/png;base64,..."
  }
}

Response 202 Accepted:
{
  "jobId": "export_abc123",
  "status": "processing",
  "estimatedTime": 30  // segundos
}

GET /api/v2/exports/{jobId}
Response 200 OK:
{
  "status": "completed",
  "downloadUrl": "/downloads/report_abc123.pdf",
  "fileSize": 2458624,  // bytes
  "pages": 45
}
```

---

#### 🎫 US-402: Exportação Excel/CSV

**Como** analista de dados,
**Quero** exportar checklists para Excel/CSV,
**Para que** eu faça análises personalizadas e dashboards no Power BI.

**Critérios de Aceitação:**
- [ ] Botão "Exportar para Excel"
- [ ] Arquivo .xlsx com múltiplas abas:
  - **Resumo:** Métricas gerais
  - **Por Categoria:** Uma aba para cada categoria (Web, API, Mobile)
  - **Por Status:** Itens Failed, Passed, N/A
  - **Timeline:** Histórico de ações
- [ ] Formatação condicional (células vermelhas para Failed)
- [ ] Opção alternativa: CSV simples (flat, todas as colunas)
- [ ] Delimitador configurável (vírgula, ponto-e-vírgula, tab)

**Biblioteca:** exceljs (Node.js) ou xlsx (frontend)

---

#### 🎫 US-403: API JSON para Integrações

**Como** engenheiro de DevOps,
**Quero** acessar dados via API JSON,
**Para que** eu integre com JIRA, Slack, CI/CD pipelines.

**Critérios de Aceitação:**
- [ ] Endpoint público: `GET /api/v2/projects/{id}/export/json`
- [ ] Autenticação via API Key (gerada no settings)
- [ ] Response completo com todos os dados estruturados
- [ ] Rate limiting: 100 req/hora
- [ ] Documentação no formato OpenAPI 3.0 (Swagger)
- [ ] Webhooks (opcional): Notificar URL externa quando projeto atualiza

**Exemplo Response:**
```json
{
  "project": {
    "id": "proj_123",
    "name": "API de Pagamentos v2.1",
    "status": "active",
    "progress": 65,
    "categories": ["owasp-web", "api-security"],
    "items": [
      {
        "id": "item_abc",
        "category": "A01",
        "title": "Revisar BOLA",
        "status": "failed",
        "severity": "critical",
        "assignee": "Ana Silva",
        "notes": "BOLA detectado em /users/{id}",
        "evidences": [
          {"name": "screenshot.png", "url": "/uploads/..."}
        ]
      }
    ],
    "metadata": {
      "createdAt": "2025-11-01T00:00:00Z",
      "updatedAt": "2025-11-09T10:00:00Z"
    }
  }
}
```

---

#### 🎫 US-404: Agendamento de Relatórios

**Como** gerente de segurança,
**Quero** agendar geração automática de relatórios semanais,
**Para que** eu receba updates sem intervenção manual.

**Critérios de Aceitação:**
- [ ] Configuração em Settings do projeto
- [ ] Opções de frequência: Diária, Semanal, Quinzenal, Mensal
- [ ] Destinatários (emails múltiplos)
- [ ] Formato: PDF Executivo por padrão
- [ ] Preview do próximo envio agendado
- [ ] Log de envios anteriores
- [ ] Possibilidade de cancelar/pausar agendamento

**Stack:** node-cron ou agenda (job scheduling)

---

### ÉPICO 5: Offline & PWA (COULD HAVE) 🟢

**Objetivo:** Permitir uso offline com sincronização posterior.

**Valor de Negócio:** Médio — Útil para pentests em ambientes sem internet.

**Estimativa:** 13 Story Points (Sprint 5)

---

#### 🎫 US-501: Progressive Web App (PWA)

**Como** pentester em campo,
**Quero** usar o dashboard offline,
**Para que** eu trabalhe em locais sem conexão (data centers isolados).

**Critérios de Aceitação:**
- [ ] Manifest.json com ícones e cores
- [ ] Service Worker que cacheia:
  - Assets estáticos (HTML, CSS, JS, imagens)
  - Dados do projeto atual (IndexedDB)
  - Checklists (data.mjs)
- [ ] Modo offline detectado automaticamente (navigator.onLine)
- [ ] Banner: "Você está offline. Dados serão sincronizados quando conectar"
- [ ] Queue de mudanças pendentes
- [ ] Sincronização automática ao reconectar
- [ ] Conflitos resolvidos por timestamp (last-write-wins)
- [ ] Instalável como app (Chrome, Edge, Safari)

**Tecnologias:**
- Workbox (Google)
- IndexedDB para storage local
- Background Sync API

---

#### 🎫 US-502: Sincronização Inteligente

**Como** analista de segurança,
**Quero** que mudanças offline sejam sincronizadas automaticamente,
**Para que** eu não perca trabalho.

**Critérios de Aceitação:**
- [ ] Queue persiste em IndexedDB (não se perde ao fechar aba)
- [ ] Retry automático em caso de falha (exponential backoff)
- [ ] Indicador visual: "3 mudanças pendentes de sincronização"
- [ ] Botão "Forçar sincronização agora"
- [ ] Resolução de conflitos: Mostrar diff e permitir escolher versão

---

### ÉPICO 6: Internacionalização (COULD HAVE) 🟢

**Objetivo:** Suportar múltiplos idiomas (pt-BR, en-US, es-ES).

**Valor de Negócio:** Médio — Expande mercado internacional.

**Estimativa:** 8 Story Points (Sprint 6)

---

#### 🎫 US-601: Multi-idioma no Frontend

**Como** usuário internacional,
**Quero** usar o dashboard em inglês/espanhol,
**Para que** minha equipe global colabore melhor.

**Critérios de Aceitação:**
- [ ] Seletor de idioma no header
- [ ] 3 idiomas iniciais: pt-BR, en-US, es-ES
- [ ] Toda UI traduzida (botões, labels, tooltips, mensagens de erro)
- [ ] Formatação de datas/horas localizada (Intl.DateTimeFormat)
- [ ] Números formatados (Intl.NumberFormat)
- [ ] Preferência salva no perfil do usuário
- [ ] Fallback para inglês se tradução não existir

**Stack:** i18next ou react-intl

**Estrutura de Arquivos:**
```
/locales
  /pt-BR
    common.json
    dashboard.json
    checklist.json
  /en-US
    common.json
    dashboard.json
    checklist.json
  /es-ES
    common.json
    dashboard.json
    checklist.json
```

---

#### 🎫 US-602: Relatórios Multi-idioma

**Como** consultor internacional,
**Quero** gerar relatórios em inglês,
**Para que** clientes estrangeiros entendam.

**Critérios de Aceitação:**
- [ ] Opção "Idioma do relatório" no modal de exportação
- [ ] Templates traduzidos (capa, seções, labels)
- [ ] Conteúdo técnico traduzido (títulos de itens, categorias)
- [ ] Manter notas/comentários no idioma original (com flag de idioma)

---

### ÉPICO 7: Segurança do Aplicativo (MUST HAVE) ⭐⭐

**Objetivo:** Proteger a aplicação contra ameaças (irônico um app de segurança ser inseguro!).

**Valor de Negócio:** CRÍTICO — Requisito para empresas enterprise.

**Estimativa:** 21 Story Points (Sprint 1-2)

---

#### 🎫 US-701: Autenticação JWT

**Como** usuário da plataforma,
**Quero** fazer login com credenciais seguras,
**Para que** apenas pessoas autorizadas acessem dados sensíveis.

**Critérios de Aceitação:**
- [ ] Tela de login com email + senha
- [ ] Hashing de senhas com bcrypt (salt rounds >= 12)
- [ ] JWT assinado com HS256 ou RS256
- [ ] Access token (15min TTL) + Refresh token (7 dias)
- [ ] Refresh automático antes de expirar
- [ ] Logout limpa tokens (blacklist no backend)
- [ ] Proteção contra brute force (rate limiting: 5 tentativas/IP/15min)
- [ ] MFA opcional (TOTP via Google Authenticator)

**Endpoint API:**
```http
POST /api/v2/auth/login
Content-Type: application/json

{
  "email": "ana@empresa.com",
  "password": "SecureP@ssw0rd!"
}

Response 200 OK:
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "user-123",
    "name": "Ana Silva",
    "email": "ana@empresa.com",
    "role": "admin"
  }
}
```

---

#### 🎫 US-702: Sanitização de Inputs (Anti-XSS)

**Como** desenvolvedor,
**Quero** que todos os inputs sejam sanitizados,
**Para que** não haja vulnerabilidades XSS na própria ferramenta.

**Critérios de Aceitação:**
- [ ] Biblioteca DOMPurify para sanitizar HTML
- [ ] Validação de entrada no backend (Joi/Zod schemas)
- [ ] Content Security Policy (CSP) habilitado
- [ ] Escapar outputs em templates
- [ ] Validação de uploads (MIME type whitelist)
- [ ] Limite de tamanho de arquivo (10 MB)

**CSP Header:**
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  img-src 'self' data: https:;
  font-src 'self' https://fonts.gstatic.com;
  connect-src 'self' https://api.appsec-dashboard.com;
```

---

#### 🎫 US-703: Controle de Acesso (RBAC)

**Como** administrador,
**Quero** que usuários só acessem recursos autorizados,
**Para que** não haja vazamento de dados entre projetos.

**Critérios de Aceitação:**
- [ ] Middleware de autorização em todas as rotas
- [ ] Verificação: Usuário pertence ao projeto?
- [ ] Verificação: Role permite a ação?
- [ ] Log de auditoria (quem acessou o quê, quando)
- [ ] Proteção contra IDOR (validar ownership)

**Middleware Exemplo:**
```javascript
async function authorizeProjectAccess(req, res, next) {
  const { projectId } = req.params;
  const userId = req.user.id;

  const isMember = await db.projects.isMember(projectId, userId);
  if (!isMember) {
    return res.status(403).json({ error: "Forbidden" });
  }

  next();
}
```

---

#### 🎫 US-704: Validação de Uploads (Anti-Malware)

**Como** administrador de segurança,
**Quero** que arquivos enviados sejam verificados,
**Para que** não haja upload de malware.

**Critérios de Aceitação:**
- [ ] Whitelist de MIME types: image/*, application/pdf, text/plain
- [ ] Magic number validation (não confiar em extensão)
- [ ] Antivirus scan com ClamAV (opcional, se viável)
- [ ] Limite de tamanho: 10 MB por arquivo
- [ ] Armazenamento fora do webroot
- [ ] URLs assinadas para download (expirável)

**Validação de MIME Type:**
```javascript
import fileType from 'file-type';

const allowedTypes = ['image/png', 'image/jpeg', 'application/pdf', 'text/plain'];

async function validateUpload(buffer) {
  const type = await fileType.fromBuffer(buffer);
  if (!type || !allowedTypes.includes(type.mime)) {
    throw new Error('Tipo de arquivo não permitido');
  }
}
```

---

#### 🎫 US-705: Rate Limiting & DDoS Protection

**Como** administrador de infraestrutura,
**Quero** proteger APIs contra abuse,
**Para que** o serviço permaneça disponível.

**Critérios de Aceitação:**
- [ ] Rate limiting por IP e por usuário
- [ ] Limites:
  - Login: 5 req/15min
  - API leitura: 100 req/min
  - API escrita: 30 req/min
  - Exports: 5 req/hora
- [ ] Response headers: X-RateLimit-Remaining, X-RateLimit-Reset
- [ ] Status 429 Too Many Requests com Retry-After
- [ ] Cloudflare ou AWS WAF para DDoS L7

**Implementação:**
```javascript
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5,
  message: 'Muitas tentativas de login. Tente novamente em 15 minutos.'
});

app.post('/api/v2/auth/login', loginLimiter, loginHandler);
```

---

### ÉPICO 8: Responsividade Mobile (SHOULD HAVE) 🟡

**Objetivo:** Adaptar interface para tablets e smartphones.

**Valor de Negócio:** Médio — Alguns pentesters trabalham com tablets.

**Estimativa:** 13 Story Points (Sprint 4)

---

#### 🎫 US-801: Layout Responsivo

**Como** usuário mobile,
**Quero** navegar checklists no smartphone,
**Para que** eu revise achados em movimento.

**Critérios de Aceitação:**
- [ ] Breakpoints: 320px (mobile), 768px (tablet), 1024px (desktop)
- [ ] Sidebar vira hamburger menu (<768px)
- [ ] Cards empilhados verticalmente (1 coluna)
- [ ] Touch-friendly: Botões >= 44x44px
- [ ] Gestos: Swipe para fechar modal
- [ ] Inputs adaptados (type="email", type="tel")
- [ ] Zoom permitido (não bloquear com maximum-scale)

---

#### 🎫 US-802: Performance em Mobile

**Como** usuário com 3G,
**Quero** que o app carregue rápido,
**Para que** não desperdice meu plano de dados.

**Critérios de Aceitação:**
- [ ] Bundle JS < 300 KB (gzipped)
- [ ] Lazy loading de imagens
- [ ] Code splitting por rota
- [ ] Prefetch de dados críticos
- [ ] Lighthouse score >= 90 (Performance, Accessibility)

---

## 🗓️ Roadmap de Releases

### Release 1.0 MVP (Sprint 1-2) — 8 semanas

**Objetivo:** Funcionalidades essenciais para substituir versão atual.

| Épico | User Stories | Story Points |
|-------|--------------|--------------|
| **Gerenciamento de Projetos** | US-101, US-102, US-103 | 13 |
| **Dashboard Analítico** | US-201, US-202, US-203 | 21 |
| **Segurança do App** | US-701, US-702, US-703 | 21 |
| **Exportação PDF** | US-401 | 13 |
| **Total** | **9 Stories** | **68 SP** |

**Entregáveis:**
- ✅ Autenticação JWT funcionando
- ✅ CRUD de projetos
- ✅ Dashboard com métricas e gráficos
- ✅ Exportação PDF (template executivo)
- ✅ Sanitização de inputs

---

### Release 1.1 Collaboration (Sprint 3-4) — 8 semanas

**Objetivo:** Suporte a trabalho em equipe.

| Épico | User Stories | Story Points |
|-------|--------------|--------------|
| **Colaboração Multi-User** | US-301, US-302, US-303, US-304 | 34 |
| **Exportações Avançadas** | US-402, US-403 | 13 |
| **Mobile Responsivo** | US-801, US-802 | 13 |
| **Total** | **8 Stories** | **60 SP** |

**Entregáveis:**
- ✅ Atribuição de tarefas
- ✅ Comentários e menções
- ✅ RBAC (Admin/Editor/Viewer)
- ✅ Real-time collaboration (WebSockets)
- ✅ Exportação Excel/CSV
- ✅ API JSON pública
- ✅ Interface mobile-first

---

### Release 1.2 Advanced (Sprint 5-6) — 8 semanas

**Objetivo:** Features avançadas e expansão internacional.

| Épico | User Stories | Story Points |
|-------|--------------|--------------|
| **Offline & PWA** | US-501, US-502 | 13 |
| **Internacionalização** | US-601, US-602 | 8 |
| **Segurança Avançada** | US-704, US-705 | 8 |
| **Agendamento** | US-404 | 5 |
| **Total** | **6 Stories** | **34 SP** |

**Entregáveis:**
- ✅ PWA instalável
- ✅ Modo offline com sync
- ✅ Suporte a 3 idiomas
- ✅ Rate limiting
- ✅ Upload validation
- ✅ Agendamento de relatórios

---

## 📊 Matriz de Esforço vs Valor

```
        Alto Valor
            │
    US-701  │  US-101  US-401
    (Auth)  │ (Projetos)(PDF)
            │
            │  US-201
            │ (Dashboard)
────────────┼──────────────────── Alto Esforço
            │
    US-602  │  US-303  US-304
   (i18n)   │  (RBAC)  (Real-time)
            │
            │  US-501
            │  (PWA)
        Baixo Valor
```

**Legenda:**
- 🟢 **Quick Wins** (Alto Valor, Baixo Esforço): US-101, US-401, US-701
- 🟡 **Major Projects** (Alto Valor, Alto Esforço): US-201, US-301, US-402
- 🟠 **Fill-Ins** (Baixo Valor, Baixo Esforço): US-602, US-704
- 🔴 **Thankless Tasks** (Baixo Valor, Alto Esforço): US-304, US-501

**Estratégia de Priorização:**
1. Fazer todos os **Quick Wins** primeiro (Sprint 1)
2. Tacklear **Major Projects** por ordem de dependência (Sprint 2-4)
3. Preencher com **Fill-Ins** quando houver capacidade (Sprint 5-6)
4. Evitar **Thankless Tasks** a menos que sejam bloqueadores

---

## 📝 Definição de Pronto (DoD)

Checklist para considerar uma User Story como "Done":

- [ ] Código implementado e revisado (PR aprovado)
- [ ] Testes unitários escritos e passando (cobertura >= 80%)
- [ ] Testes de integração/E2E para fluxos críticos
- [ ] Documentação API atualizada (se aplicável)
- [ ] UI/UX revisada por designer
- [ ] Acessibilidade validada (WCAG 2.1 AA)
- [ ] Performance testada (Lighthouse >= 90)
- [ ] Segurança validada (OWASP Top 10)
- [ ] Deploy em staging realizado
- [ ] QA manual executado e aprovado
- [ ] Product Owner aprovou feature

---

## 📞 Contato & Feedback

**Product Manager:** [produto@appsec-dashboard.com](mailto:produto@appsec-dashboard.com)
**Roadmap atualizado:** [roadmap.appsec-dashboard.com](https://roadmap.appsec-dashboard.com)

---

**Documento vivo** — Backlog revisado a cada Sprint Planning.
