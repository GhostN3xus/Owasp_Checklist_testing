# 🎨 Redesign UX/UI — AppSec Dashboard v2.0

**Versão:** 2.0.0
**Data:** 2025-11-09
**Autor:** Equipe de Produto & UX

---

## 📋 Índice

1. [Visão Geral](#visão-geral)
2. [Problemas Atuais](#problemas-atuais)
3. [Wireframes do Novo Design](#wireframes-do-novo-design)
4. [Sistema de Design](#sistema-de-design)
5. [Fluxos de Usuário](#fluxos-de-usuário)
6. [Acessibilidade & Responsividade](#acessibilidade--responsividade)

---

## 🎯 Visão Geral

### Objetivo do Redesign
Transformar o AppSec Dashboard de uma **ferramenta de checklist linear** em uma **plataforma colaborativa de gestão de segurança** que oferece:

- **Navegação por projetos** (não apenas checklists)
- **Dashboard analítico** com insights acionáveis
- **Colaboração em equipe** com atribuições e filtros
- **Exportações profissionais** integradas
- **Responsividade mobile-first**
- **Acessibilidade WCAG 2.1 AA**

### Princípios de Design

| Princípio | Implementação |
|-----------|---------------|
| **Progressive Disclosure** | Mostrar apenas o essencial, revelar detalhes sob demanda |
| **Data Density** | Maximizar informação útil sem poluição visual |
| **Feedback Imediato** | Toda ação tem resposta visual em <100ms |
| **Consistência** | Padrões repetíveis em todo o app |
| **Autonomia** | Usuário controla o que vê e quando |

---

## 🔴 Problemas Atuais

### Navegação & Descoberta
- ❌ **Sem contexto de projeto**: Todos os checklists em uma única sessão
- ❌ **Busca limitada**: Apenas filtro por texto, sem facets
- ❌ **Sidebar sobrecarregada**: 13 categorias + workflow timeline + botões
- ❌ **Sem breadcrumbs**: Usuário perde contexto de onde está

### Visualização de Dados
- ❌ **Métricas básicas**: Apenas 4 cards (total, concluído, falhas, evidências)
- ❌ **Sem analytics**: Nenhuma visualização de tendências ou riscos
- ❌ **Progress genérico**: Apenas % geral, sem breakdown por categoria

### Colaboração
- ❌ **Single-user**: Sem suporte real a múltiplos testers
- ❌ **Sem histórico**: Impossível rastrear quem fez o quê
- ❌ **Atribuições manuais**: Campo de texto livre (sem autocomplete)

### Exportação
- ❌ **PDF via print**: Quebra formatação, sem controle
- ❌ **Sem templates**: Relatório sempre igual
- ❌ **Sem scheduling**: Exportação sempre manual

### Mobile & Acessibilidade
- ❌ **Não responsivo**: Layout quebra <768px
- ❌ **Sem ARIA**: Navegação ruim com screen readers
- ❌ **Contrast issues**: Alguns textos não passam WCAG AA

---

## 🖼️ Wireframes do Novo Design

### Layout Geral (4 Telas Principais)

```
┌─────────────────────────────────────────────────────────────────┐
│  NOVA ARQUITETURA DE INFORMAÇÃO                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 🗂️  TELA: LISTA DE PROJETOS (Landing)                      │
│  2. 📊  TELA: DASHBOARD ANALÍTICO (Por projeto)                │
│  3. ✅  TELA: VISUALIZAÇÃO DE CHECKLIST (Editor)               │
│  4. 📤  MODAL: CENTRO DE EXPORTAÇÃO                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### 1️⃣ TELA: Lista de Projetos (Landing Page)

**Propósito:** Ponto de entrada. Usuário seleciona/cria projeto antes de acessar checklists.

```
┌─────────────────────────────────────────────────────────────────────┐
│ 🔒 AppSec Dashboard v2.0              [Buscar projetos...]  👤 João │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  📊 Visão Geral dos Projetos                     [+ Novo Projeto]  │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                     │
│  Filtros: [Todos ▼] [Meus Projetos] [Em Andamento] [Arquivados]   │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 🌐 API de Pagamentos v2.1              🟢 Em andamento        │ │
│  │ ──────────────────────────────────────────────────────────────│ │
│  │ Team: Ana Silva, João Pentester, Maria QA                     │ │
│  │ Última atualização: 2 horas atrás por Ana                     │ │
│  │                                                               │ │
│  │ Progress: ████████████░░░░░░░░░░ 65% (195/300 itens)         │ │
│  │                                                               │ │
│  │ Riscos: 🔴 12 críticos  🟡 34 médios  🟢 8 baixos            │ │
│  │                                                               │ │
│  │ [Ver Dashboard] [Continuar Checklist] [Exportar] [⋯]         │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ 📱 App Mobile Banking                  🟡 Revisão pendente    │ │
│  │ ──────────────────────────────────────────────────────────────│ │
│  │ Team: Pedro iOS, Carla Android                                │ │
│  │ Última atualização: 1 dia atrás                               │ │
│  │                                                               │ │
│  │ Progress: ██████░░░░░░░░░░░░░░░░ 30% (45/150 itens)          │ │
│  │                                                               │ │
│  │ [Ver Dashboard] [Continuar Checklist] [⋯]                     │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │ ☁️ Cloud Migration AWS                 ✅ Concluído           │ │
│  │ ──────────────────────────────────────────────────────────────│ │
│  │ Team: DevOps Team                                             │ │
│  │ Concluído: 15 dias atrás                                      │ │
│  │                                                               │ │
│  │ Progress: ████████████████████ 100% (180/180 itens)          │ │
│  │                                                               │ │
│  │ [Ver Relatório Final] [Arquivar] [⋯]                          │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Componentes Chave:**

| Elemento | Descrição |
|----------|-----------|
| **Card de Projeto** | Mostra nome, team, progresso, riscos e ações rápidas |
| **Badges de Status** | 🟢 Em andamento, 🟡 Revisão, ✅ Concluído, ⏸️ Pausado |
| **Progress Bar** | Visual + percentual + contador (X/Y itens) |
| **Risk Summary** | Indicadores coloridos de severidade |
| **Quick Actions** | Ver Dashboard, Continuar, Exportar |
| **Filtros** | Por status, responsável, data |

---

### 2️⃣ TELA: Dashboard Analítico (Por Projeto)

**Propósito:** Visão gerencial do projeto com insights e analytics.

```
┌─────────────────────────────────────────────────────────────────────┐
│ ← Projetos  /  API de Pagamentos v2.1                    👤 João    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  📊 Dashboard — API de Pagamentos v2.1                              │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │  CARDS DE MÉTRICAS (Grid 2x3)                              │   │
│  ├────────────┬────────────┬────────────┬────────────────────┐   │
│  │ 📝 Total   │ ✅ Passou  │ ❌ Falhou  │ ⚠️ Não Aplicável   │   │
│  │ 300 itens  │ 145 (48%)  │ 54 (18%)   │ 23 (8%)            │   │
│  ├────────────┼────────────┼────────────┼────────────────────┤   │
│  │ 🔄 Pend.   │ 📎 Evid.   │ 👥 Team    │ ⏱️ Tempo          │   │
│  │ 78 (26%)   │ 132 anexos │ 3 pessoas  │ 12 dias            │   │
│  └────────────┴────────────┴────────────┴────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────┬─────────────────────────────────────┐ │
│  │  COBERTURA POR CATEGORIA│  TOP 5 RISCOS CRÍTICOS              │ │
│  │  ─────────────────────  │  ─────────────────────────────────  │ │
│  │                         │                                     │ │
│  │  ┌──────────────────┐   │  1. 🔴 BOLA em /users/{id}         │ │
│  │  │                  │   │     (A01 — Broken Access Control)  │ │
│  │  │    [Gráfico      │   │     Assignee: Ana Silva            │ │
│  │  │     Radial       │   │     Evidências: 3 anexos           │ │
│  │  │     Multi-       │   │                                     │ │
│  │  │     Categoria]   │   │  2. 🔴 SQL Injection em /search    │ │
│  │  │                  │   │     (A03 — Injection)              │ │
│  │  │   Web: 75%       │   │     Assignee: João Pentester       │ │
│  │  │   API: 60%       │   │                                     │ │
│  │  │   Mobile: 45%    │   │  3. 🔴 JWT sem expiração           │ │
│  │  │                  │   │     (A07 — Auth Failures)          │ │
│  │  └──────────────────┘   │     Assignee: Maria QA             │ │
│  │                         │                                     │ │
│  │  [Ver Detalhes →]       │  4. 🟠 XSS refletido em /comments  │ │
│  │                         │  5. 🟠 Ausência de Rate Limiting   │ │
│  │                         │                                     │ │
│  │                         │  [Ver Todos os Riscos →]           │ │
│  └─────────────────────────┴─────────────────────────────────────┘ │
│                                                                     │
│  ┌─────────────────────────┬─────────────────────────────────────┐ │
│  │  WORKFLOW TIMELINE      │  ATIVIDADE RECENTE                  │ │
│  │  ─────────────────────  │  ─────────────────────────────────  │ │
│  │                         │                                     │ │
│  │  📡 Recon     ████ 80%  │  • Ana marcou A01-5 como "Falhou"  │ │
│  │  🧪 Testing   ███░ 65%  │    há 2 horas                       │ │
│  │  🛂 Access    ██░░ 50%  │                                     │ │
│  │  📝 Report    █░░░ 25%  │  • João anexou screenshot em A03-2 │ │
│  │  🛡️ Mitigate  ░░░░ 10%  │    há 5 horas                       │ │
│  │                         │                                     │ │
│  │  [Ver Breakdown →]      │  • Maria atualizou notas em A07-1  │ │
│  │                         │    ontem                            │ │
│  │                         │                                     │ │
│  │                         │  [Ver Histórico Completo →]        │ │
│  └─────────────────────────┴─────────────────────────────────────┘ │
│                                                                     │
│  [🗂️ Ir para Checklists]  [📤 Exportar Relatório]  [⚙️ Config.]  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Visualizações Incluídas:**

| Seção | Tipo | Dados |
|-------|------|-------|
| **Métricas Gerais** | Cards numéricos | Total, Passou, Falhou, N/A, Pendentes, Evidências, Team, Tempo |
| **Cobertura** | Gráfico radial/donut | % de conclusão por categoria (Web, API, Mobile, Cloud...) |
| **Top Riscos** | Lista rankeada | 5 itens críticos ordenados por severidade + assignee + evidências |
| **Workflow** | Progress bars horizontais | % de conclusão por fase (Recon → Mitigate) |
| **Atividade** | Timeline reversa | Últimas 10 ações (quem, o quê, quando) |
| **Gaps** | Heatmap | Seções com menor cobertura (identificar lacunas) |

---

### 3️⃣ TELA: Visualização de Checklist (Editor)

**Propósito:** Interface principal de trabalho do pentester/analista.

**Layout: 3 Colunas Responsivas**

```
┌─────────────────────────────────────────────────────────────────────┐
│ ← Dashboard  /  API de Pagamentos  /  OWASP Web — A01              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────┬──────────────────────────────────────┬─────────────┐ │
│  │          │                                      │             │ │
│  │  SIDEBAR │  MAIN CONTENT                        │  SIDE PANEL │ │
│  │  (Nav)   │  (Checklist Items)                   │  (Filters)  │ │
│  │          │                                      │             │ │
│  │  [Seções]│  ┌────────────────────────────────┐  │  [Filtros]  │ │
│  │          │  │ ✅ A01-1 Revisar controles     │  │             │ │
│  │  • A01   │  │ ────────────────────────────── │  │  Status:    │ │
│  │    Acesso│  │ 🔴 FAILED  •  🚨 CRITICAL      │  │  [Todos ▼]  │ │
│  │          │  │ 👤 Ana Silva  •  📝 Report     │  │             │ │
│  │  • A02   │  │                                │  │  Assignee:  │ │
│  │    Crypto│  │ [Ver Guia] [Evidências: 3]    │  │  [Todos ▼]  │ │
│  │          │  └────────────────────────────────┘  │             │ │
│  │  • A03   │                                      │  Fase:      │ │
│  │    Inject│  ┌────────────────────────────────┐  │  [Todas ▼]  │ │
│  │          │  │ ⬜ A01-2 Testar IDOR            │  │             │ │
│  │  • A04   │  │ ────────────────────────────── │  │  Busca:     │ │
│  │    Design│  │ ⚪ NOT TESTED  •  🟡 MEDIUM    │  │  [______]   │ │
│  │          │  │ 👤 Não atribuído  •  🧪 Test  │  │             │ │
│  │  ...     │  │                                │  │  [Aplicar]  │ │
│  │          │  │ [Atribuir] [Testar]            │  │             │ │
│  │  [13     │  └────────────────────────────────┘  │             │ │
│  │  categ.] │                                      │  ──────────  │ │
│  │          │  ┌────────────────────────────────┐  │             │ │
│  │          │  │ ✅ A01-3 Path traversal        │  │  ATALHOS:   │ │
│  │          │  │ ────────────────────────────── │  │             │ │
│  │          │  │ 🟢 PASSED  •  🔵 INFO         │  │  [Meus      │ │
│  │          │  │ 👤 João  •  ✅ Mitigado       │  │   Items]    │ │
│  │          │  │                                │  │             │ │
│  │          │  │ [Ver Guia] [Evidências: 0]    │  │  [Críticos  │ │
│  │          │  └────────────────────────────────┘  │   Abertos]  │ │
│  │          │                                      │             │ │
│  │          │  [Mostrando 3 de 30 itens]          │  [Sem       │ │
│  │          │  [Carregar mais...]                 │   Evid.]    │ │
│  │          │                                      │             │ │
│  └──────────┴──────────────────────────────────────┴─────────────┘ │
│                                                                     │
│  Progress da Seção A01: ████████░░ 80% (24/30)  [Marcar todas]    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**ITEM CARD EXPANDIDO (Detalhes ao clicar)**

```
┌───────────────────────────────────────────────────────────────────┐
│ ✅ A01-1 — Revisar controles de acesso quebrados      [Fechar ✖]  │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  🏷️ Metadados                                                     │
│  ──────────────────────────────────────────────────────────────   │
│  Status: [Failed ▼]  Severidade: [Critical ▼]  Fase: [Report ▼]  │
│  Assignee: [Ana Silva ▼]  Priority: [P0 — Imediato ▼]            │
│                                                                   │
│  📝 Notas Técnicas                                                │
│  ──────────────────────────────────────────────────────────────   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Identificado BOLA em /api/users/{id}. Usuário com           │ │
│  │ role=viewer consegue acessar dados de admin ao modificar    │ │
│  │ o parâmetro ID na URL.                                       │ │
│  │                                                              │ │
│  │ Payload: GET /api/users/999 (ID de admin)                   │ │
│  │ Response: 200 OK com dados sensíveis                         │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  📎 Evidências (3 anexos)                                         │
│  ──────────────────────────────────────────────────────────────   │
│  ✅ Screenshot BOLA.png (125 KB)              [Visualizar] [🗑️]  │
│  ✅ Burp Request.txt (8 KB)                   [Visualizar] [🗑️]  │
│  ✅ Response JSON.json (15 KB)                [Visualizar] [🗑️]  │
│                                                                   │
│  [📤 Upload Nova Evidência]                                       │
│                                                                   │
│  ✅ Checklist de Evidências Completas                             │
│  ──────────────────────────────────────────────────────────────   │
│  ☑️ Screenshot da vulnerabilidade                                │
│  ☑️ Logs do servidor/requisições                                 │
│  ☑️ Payload utilizado                                             │
│  ☑️ Descrição do impacto                                          │
│                                                                   │
│  📘 Guia Técnico (OWASP)                                          │
│  ──────────────────────────────────────────────────────────────   │
│  [🔗 Ver Guia Completo: Broken Access Control]                   │
│  [🔗 OWASP Testing Guide v4.2 — WSTG-AUTHZ-01]                   │
│  [🔗 Cheat Sheet: Authorization]                                  │
│                                                                   │
│  [💾 Salvar Alterações]  [📤 Exportar Este Item]  [❌ Cancelar]  │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

**Melhorias na Visualização:**

| Feature | Descrição |
|---------|-----------|
| **Lazy Loading** | Carregar apenas 10-20 itens por vez (infinite scroll) |
| **Busca Instantânea** | Filtro em tempo real sem reload |
| **Bulk Actions** | Selecionar múltiplos items → Atribuir, Mudar status, Exportar |
| **Keyboard Shortcuts** | `j/k` navegar, `e` editar, `s` salvar, `esc` fechar |
| **Drag & Drop Upload** | Arrastar arquivo diretamente no card |
| **Rich Text Editor** | Markdown support para notas (syntax highlight de payloads) |
| **Auto-save** | Salvar a cada 3 segundos (debounced) |
| **Undo/Redo** | Ctrl+Z / Ctrl+Y para reverter mudanças |

---

### 4️⃣ MODAL: Centro de Exportação

**Propósito:** Hub centralizado para todas as opções de exportação profissional.

```
┌───────────────────────────────────────────────────────────────────┐
│                  📤 Centro de Exportação                [Fechar ✖]│
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Selecione o formato e personalize seu relatório                 │
│                                                                   │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┐       │
│  │             │             │             │             │       │
│  │  📄 PDF     │  📊 Excel   │  📋 CSV     │  🔌 JSON    │       │
│  │  Executivo  │  Analítico  │  Dados Brut │  API Export │       │
│  │             │             │             │             │       │
│  │  [Selecionar│  [Selecionar│  [Selecionar│  [Selecionar│       │
│  └─────────────┴─────────────┴─────────────┴─────────────┘       │
│                                                                   │
│  ──────────────────────────────────────────────────────────────   │
│                                                                   │
│  📄 Configurações do Relatório PDF                                │
│  ──────────────────────────────────────────────────────────────   │
│                                                                   │
│  Template:  [Executivo Completo ▼]                                │
│             • Executivo Completo (C-level)                        │
│             • Técnico Detalhado (Desenvolvedores)                 │
│             • Compliance (Auditores)                              │
│             • Quick Summary (Stakeholders)                        │
│                                                                   │
│  Incluir:   ☑️ Capa personalizada                                │
│             ☑️ Sumário executivo                                  │
│             ☑️ Gráficos e métricas                                │
│             ☑️ Tabela de itens (apenas failed/passed)             │
│             ☑️ Screenshots e evidências                           │
│             ☑️ Recomendações de mitigação                         │
│             ☑️ Referências OWASP                                  │
│             ☐ Anexar payloads completos                           │
│                                                                   │
│  Filtros:   ☑️ Apenas itens com status "Failed"                  │
│             ☐ Incluir itens "Not Tested"                          │
│             ☑️ Severidade >= Medium                               │
│                                                                   │
│  Idioma:    [Português 🇧🇷 ▼]  (EN, ES, FR disponíveis)          │
│                                                                   │
│  ──────────────────────────────────────────────────────────────   │
│                                                                   │
│  📅 Agendamento (Opcional)                                        │
│  ──────────────────────────────────────────────────────────────   │
│  ☐ Gerar relatório automaticamente                               │
│     Frequência: [Semanal ▼]  Enviar para: [email@empresa.com]    │
│                                                                   │
│  ──────────────────────────────────────────────────────────────   │
│                                                                   │
│  Tamanho estimado: ~2.5 MB  |  45 páginas  |  132 evidências     │
│                                                                   │
│  [⬇️ Gerar e Baixar]  [📧 Gerar e Enviar Email]  [❌ Cancelar]   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

**Opções de Exportação:**

| Formato | Casos de Uso | Customizações |
|---------|--------------|---------------|
| **PDF Executivo** | Apresentação para C-level | Template, idioma, filtros |
| **PDF Técnico** | Equipe de desenvolvimento | Inclui payloads, comandos, referencias |
| **Excel** | Análise e filtros personalizados | Múltiplas abas (por categoria, por status) |
| **CSV** | Integração com outras ferramentas | Delimitador, encoding |
| **JSON** | API exports / CI/CD integration | Schema configurável |
| **Markdown** | Documentação técnica | Para wikis internas |

---

## 🎨 Sistema de Design

### Design Tokens (Atualizado)

#### Cores (Dark Mode + Light Mode)

| Token | Dark | Light | Uso |
|-------|------|-------|-----|
| `--bg-primary` | `#0e1f2f` | `#ffffff` | Background principal |
| `--bg-elevated` | `#132a3f` | `#f8f9fa` | Cards, modais |
| `--bg-subtle` | `#17344b` | `#e9ecef` | Sidebar, footer |
| `--surface` | `#1d3d58` | `#dee2e6` | Inputs, selects |
| `--accent` | `#00c6ff` | `#0066cc` | CTAs, links |
| `--success` | `#3ddc97` | `#28a745` | Passed |
| `--danger` | `#ff6b6b` | `#dc3545` | Failed |
| `--warning` | `#ffd166` | `#ffc107` | N/A |
| `--text-primary` | `#f8f9fa` | `#212529` | Títulos |
| `--text-secondary` | `#d1d5db` | `#6c757d` | Descrições |

#### Tipografia

```css
--font-family-base: 'Inter', -apple-system, system-ui, sans-serif;
--font-family-mono: 'Fira Code', 'Courier New', monospace;

--font-size-xs: 0.75rem;    /* 12px */
--font-size-sm: 0.875rem;   /* 14px */
--font-size-base: 1rem;     /* 16px */
--font-size-lg: 1.125rem;   /* 18px */
--font-size-xl: 1.5rem;     /* 24px */
--font-size-2xl: 2rem;      /* 32px */
--font-size-3xl: 3rem;      /* 48px */

--font-weight-normal: 400;
--font-weight-medium: 500;
--font-weight-semibold: 600;
--font-weight-bold: 700;
```

#### Espaçamento (8px Base)

```css
--spacing-1: 0.25rem;  /* 4px */
--spacing-2: 0.5rem;   /* 8px */
--spacing-3: 0.75rem;  /* 12px */
--spacing-4: 1rem;     /* 16px */
--spacing-5: 1.25rem;  /* 20px */
--spacing-6: 1.5rem;   /* 24px */
--spacing-8: 2rem;     /* 32px */
--spacing-10: 2.5rem;  /* 40px */
--spacing-12: 3rem;    /* 48px */
```

#### Bordas & Sombras

```css
--radius-sm: 4px;
--radius-md: 8px;
--radius-lg: 16px;
--radius-xl: 24px;
--radius-full: 9999px;

--shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.12);
--shadow-md: 0 4px 12px rgba(0, 0, 0, 0.15);
--shadow-lg: 0 10px 30px rgba(0, 0, 0, 0.2);
--shadow-xl: 0 20px 50px rgba(0, 0, 0, 0.25);
```

### Componentes Reutilizáveis

#### Button Variants

```html
<!-- Primary -->
<button class="btn btn-primary">Salvar</button>

<!-- Secondary -->
<button class="btn btn-secondary">Cancelar</button>

<!-- Danger -->
<button class="btn btn-danger">Deletar Projeto</button>

<!-- Ghost -->
<button class="btn btn-ghost">Ver Mais</button>

<!-- Icon Only -->
<button class="btn btn-icon" aria-label="Fechar">
  <svg>...</svg>
</button>
```

#### Status Badges

```html
<span class="badge badge-success">Passed</span>
<span class="badge badge-danger">Failed</span>
<span class="badge badge-warning">N/A</span>
<span class="badge badge-secondary">Not Tested</span>
```

#### Progress Bar

```html
<div class="progress" role="progressbar" aria-valuenow="65" aria-valuemin="0" aria-valuemax="100">
  <div class="progress-bar" style="width: 65%">65%</div>
</div>
```

---

## 🔄 Fluxos de Usuário

### Fluxo 1: Novo Pentest (Happy Path)

```
1. Login → Dashboard
   ↓
2. [+ Novo Projeto]
   ↓
3. Modal: Preencher nome, team, categorias
   ↓
4. Projeto criado → Redireciona para Checklist vazio
   ↓
5. Seleciona categoria (ex: OWASP Web)
   ↓
6. Expande item A01-1
   ↓
7. Marca status como "Failed", adiciona notas
   ↓
8. Upload de screenshot (drag & drop)
   ↓
9. Auto-save confirmado (toast)
   ↓
10. Continua testando outros itens...
   ↓
11. Vai para Dashboard → Vê métricas atualizadas
   ↓
12. Exporta PDF Executivo
```

### Fluxo 2: Colaboração Multi-Tester

```
1. Ana cria projeto "API v2.1"
   ↓
2. Atribui A01-* para João, A03-* para Maria
   ↓
3. João recebe notificação → Acessa projeto
   ↓
4. Filtra por "Assignee: João"
   ↓
5. Vê apenas seus itens (A01-1 a A01-10)
   ↓
6. Trabalha nos itens, adiciona evidências
   ↓
7. Ana vê em "Atividade Recente" as ações de João
   ↓
8. Maria finaliza seus itens → Marca seção A03 como concluída
   ↓
9. Dashboard mostra progresso por tester
   ↓
10. Ana exporta relatório consolidado
```

### Fluxo 3: Exportação Profissional

```
1. Acessa Dashboard do projeto
   ↓
2. [📤 Exportar Relatório]
   ↓
3. Modal de Exportação abre
   ↓
4. Seleciona "PDF Executivo"
   ↓
5. Escolhe template "Compliance"
   ↓
6. Marca filtros: "Apenas Failed", "Severidade >= High"
   ↓
7. Preview mostra: 15 páginas, 23 itens
   ↓
8. [⬇️ Gerar e Baixar]
   ↓
9. Backend gera PDF (Puppeteer/pdfkit)
   ↓
10. Download automático inicia
   ↓
11. Toast: "Relatório gerado com sucesso"
```

---

## ♿ Acessibilidade & Responsividade

### WCAG 2.1 AA Compliance

| Critério | Implementação |
|----------|---------------|
| **1.4.3 Contrast** | Todos os textos têm contraste >= 4.5:1 |
| **2.1.1 Keyboard** | Todos os controles navegáveis via Tab |
| **2.4.7 Focus Visible** | Outline azul de 3px em elementos focados |
| **3.2.4 Consistent** | Navegação consistente em todas as telas |
| **4.1.2 Name, Role, Value** | ARIA labels em todos os interativos |

#### Exemplo de Markup Acessível

```html
<button
  class="btn btn-primary"
  aria-label="Exportar relatório em PDF"
  aria-describedby="export-help"
>
  📄 Exportar PDF
</button>
<span id="export-help" class="sr-only">
  Gera um relatório completo em formato PDF incluindo todas as evidências
</span>

<div
  role="alert"
  aria-live="polite"
  class="toast"
>
  Progresso salvo com sucesso
</div>
```

### Responsividade (Mobile-First)

#### Breakpoints

```css
/* Mobile (default) */
@media (min-width: 0px) {
  .layout { grid-template-columns: 1fr; }
  .sidebar { display: none; } /* Hamburger menu */
}

/* Tablet */
@media (min-width: 768px) {
  .layout { grid-template-columns: 240px 1fr; }
  .sidebar { display: block; }
}

/* Desktop */
@media (min-width: 1024px) {
  .layout { grid-template-columns: 280px 1fr 320px; }
  .side-panel { display: block; }
}

/* Large Desktop */
@media (min-width: 1440px) {
  .layout { grid-template-columns: 360px 1fr 400px; }
}
```

#### Mobile Adaptations

| Componente | Mobile (<768px) | Desktop (>1024px) |
|------------|-----------------|-------------------|
| **Sidebar** | Hamburger menu (drawer) | Sempre visível |
| **Filters** | Bottom sheet | Painel lateral |
| **Checklist Item** | 1 coluna (stack) | 3 colunas (grid) |
| **Dashboard** | Cards 1x6 (vertical) | Cards 2x3 (grid) |
| **Modal** | Full-screen | Centered overlay |

---

## 📐 Wireframe Interativo (Protótipo)

### Ferramenta Recomendada
**Figma** — Com componentes reutilizáveis e sistema de design compartilhado.

### Estrutura do Protótipo

```
Figma File: "AppSec Dashboard v2.0"
│
├── 🎨 Design System (Página 1)
│   ├── Colors
│   ├── Typography
│   ├── Components
│   └── Icons
│
├── 📱 Mobile Screens (Página 2)
│   ├── Projects List
│   ├── Dashboard
│   ├── Checklist (Drawer)
│   └── Export Modal
│
├── 💻 Desktop Screens (Página 3)
│   ├── Projects List
│   ├── Dashboard
│   ├── Checklist (3-col)
│   └── Export Modal
│
└── 🔄 Flows (Página 4)
    ├── Onboarding
    ├── New Project
    ├── Collaboration
    └── Export
```

---

## 🚀 Próximos Passos

1. **Validar Wireframes** com stakeholders e usuários finais
2. **Criar protótipo clicável** no Figma
3. **Testes de usabilidade** com 5-8 usuários reais
4. **Refinar baseado em feedback**
5. **Handoff para desenvolvimento** (specs, assets, tokens)

---

**Documento vivo** — Atualizado continuamente durante o desenvolvimento.

**Contato:** Equipe de Produto | produto@appsec-dashboard.com
