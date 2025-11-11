# 🛡️ OWASP Checklist - Modern AppSec Audit Platform

> **Enterprise-grade Application Security Checklist Manager**
> Next.js 14 + Prisma + SQLite + Docker. Complete audits with OWASP Web/API/Mobile/LLM checklists, project management, findings tracking, and professional exports.

---

## 🎯 What is this?

A **modern, production-ready AppSec audit platform** combining:

✅ **OWASP Checklists** - Web Top 10, API Security Top 10, Mobile (MASVS), LLM Top 10
✅ **Projects & Assessments** - Organize security audits and track progress
✅ **Findings Management** - Record vulnerabilities with evidence tracking
✅ **Professional Exports** - PDF/CSV/JSON reports with full assessment data
✅ **Authentication & RBAC** - Role-based access control (Admin/Analyst/User)
✅ **Local-first Architecture** - SQLite by default, easy migration to Postgres
✅ **Security-hardened** - Zod validation, rate-limiting, XSS protection, CSP headers

---

## 🚀 Funcionalidades Principais

### 📋 **13 Módulos Especializados de Segurança**

| Módulo | Descrição | Items |
|--------|-----------|-------|
| **🌐 OWASP Web Top 10** | Vulnerabilidades web críticas (2021) | 30+ |
| **🔌 OWASP API Security** | API Top 10 2023 + GraphQL | 25+ |
| **📱 Mobile Security (MASVS)** | Android & iOS (MASVS/MASTG) | 20+ |
| **☁️ Cloud Security** | AWS, Azure, GCP + Kubernetes, Docker, IaC | 30+ |
| **🧠 Threat Modeling** | STRIDE, PASTA, LINDDUN | 15+ |
| **💼 Business Logic** | Falhas de lógica de negócio | 12+ |
| **🔗 Supply Chain/SCA** | Dependências, SBOM, vulnerabilidades | 18+ |
| **📊 Logging & Monitoring** | SIEM, detecção de ameaças, incident response | 15+ |
| **🔐 Secure Code Review** | Code review e secure coding | 15+ |
| **📜 OWASP Cheat Sheets** | Input validation, XSS, Auth | 20+ |
| **🧪 SAST/DAST** | Testes estáticos e dinâmicos | 10+ |
| **⚙️ Server Hardening** | IIS, Apache, Nginx, Windows, Linux | 40+ |
| **🎯 PTES** | Penetration Testing Execution Standard | 40+ |

**Total: 300+ itens de checklist com guias completos!**

---

## 🆕 Novidades Desta Versão

### ✨ **6 Novos Módulos Completos**

1. **🔌 OWASP API Security Top 10 2023**
   - BOLA/IDOR, Broken Authentication, Mass Assignment
   - GraphQL Security (introspection, depth attacks)
   - Exemplos práticos com Burp, Postman, curl

2. **📱 Mobile Security (MASVS/MASTG)**
   - Android & iOS security testing
   - Armazenamento seguro, criptografia, biometria
   - Root/Jailbreak detection, anti-debugging
   - WebView, Deep Links, Certificate Pinning

3. **🧠 Threat Modeling**
   - STRIDE (Spoofing, Tampering, Repudiation, etc)
   - PASTA (7 estágios de análise de risco)
   - LINDDUN (privacy threat modeling)
   - Attack Trees e Kill Chain Analysis

4. **💼 Business Logic Vulnerabilities**
   - Bypass de workflow, race conditions
   - Manipulação de preços e quantidades
   - Abuse de funcionalidades legítimas
   - Timing attacks e replay

5. **🔗 Supply Chain Security & SCA**
   - Scan de dependências (npm audit, Snyk, OWASP Dependency-Check)
   - SBOM (Software Bill of Materials)
   - Dependency confusion, typosquatting
   - License compliance

6. **📊 Logging, Monitoring & Incident Response**
   - Logging seguro (o que logar, como proteger)
   - SIEM (Splunk, ELK Stack, Datadog)
   - Detection rules e alertas
   - Incident Response Plan (NIST 800-61)
   - Forensics readiness

### 🎨 **Interface Profissional Aprimorada**

- Dashboard com métricas em tempo real
- Workflow de 5 fases (Recon → Testing → Access → Report → Mitigate)
- Filtros avançados por status, tester, fase
- Campos ricos: notas, evidências, anexos, narrativas
- Sistema de tags (severity, priority, stage)

### 📄 **Exportação Profissional**

- Relatórios PDF completos com métricas
- Exportação parcial por seção
- Templates profissionais formatados
- Evidências anexadas (screenshots, logs, PoCs)

---

## 🚀 Quick Start with Docker

### **Requirements**
- Docker & Docker Compose

### **Installation**

```bash
# Clone repository
git clone https://github.com/GhostN3xus/Owasp_Checklist_testing.git
cd Owasp_Checklist_testing

# Copy example env
cp .env.example .env.local

# Start with Docker
docker compose -f docker/docker-compose.yml up --build
```

Wait for container to initialize, then open **http://localhost:3000**

### **Default Credentials**
- **Email**: `admin@local`
- **Password**: `admin123!`

### **Manual Setup (without Docker)**

```bash
# Install dependencies (requires Node.js 20+, pnpm)
pnpm install

# Setup database
pnpm migrate
pnpm seed

# Start development server
pnpm dev
```

Open **http://localhost:3000**

---

## 📖 API Endpoints

### **Authentication**
- `POST /api/v1/auth/login` - User login

### **Checklists**
- `GET /api/v1/checklists` - List all checklists
- `GET /api/v1/checklists/[slug]` - Get checklist with items

### **Projects**
- `GET /api/v1/projects` - List projects
- `POST /api/v1/projects` - Create project
- `GET /api/v1/projects/[id]` - Get project
- `PATCH /api/v1/projects/[id]` - Update project

### **Assessments**
- `GET /api/v1/assessments` - List assessments
- `POST /api/v1/assessments` - Create assessment
- `GET /api/v1/assessments/[id]` - Get assessment with progress
- `PATCH /api/v1/assessments/[id]/items/[itemId]` - Update assessment item status

### **Findings**
- `GET /api/v1/findings` - List findings
- `POST /api/v1/findings` - Create finding
- `GET /api/v1/findings/[id]` - Get finding
- `PATCH /api/v1/findings/[id]` - Update finding

### **Exports**
- `POST /api/v1/exports/pdf` - Generate PDF report
- `POST /api/v1/exports/csv` - Export CSV
- `POST /api/v1/exports/json` - Export JSON

## 📋 Adding New Checklists

1. **Create YAML file** in `packages/content/checklists/`:

```yaml
id: owasp_custom_2025
title: Custom Checklist
version: "1.0"
category: "CUSTOM"
items:
  - code: "ITEM1"
    title: "Item Title"
    description: "Item description"
    severity: "HIGH"
    cweId: "CWE-123"
    bodyMd: "# Markdown content..."
    references: "https://example.com"
    tools: "Tool1, Tool2"
    category: "Category"
    sort: 1
```

2. **Run seed**:
```bash
pnpm run seed
```

3. **New checklist appears in UI!**

## 📊 Using Como Usar

### **1. Configurar Auditoria**
- Informe nome do projeto, tester, janela de auditoria
- Escolha o módulo de segurança (API, Mobile, Web, etc)

### **2. Conduzir Testes**
Para cada item:
- ✅ Marque checkbox ao concluir
- 🎯 Defina status: **Passou** | **Falhou** | **N/A** | **Não testado**
- 🔍 Defina severidade: **Critical** | **High** | **Medium** | **Low**
- 📝 Adicione notas técnicas
- 📎 Anexe evidências (screenshots, logs, payloads)
- 📋 Use checklist de evidências (Screenshot, Logs, Payload, Impacto)

### **3. Acessar Guias Técnicos**
Clique em **"📘 Guia completo"** para ver:
- **Overview**: Contexto da vulnerabilidade
- **Impact**: Riscos e consequências
- **Detection**: Como identificar (técnicas, padrões)
- **Tools**: Ferramentas recomendadas
- **Commands**: Comandos práticos (Burp, curl, scripts)
- **Steps**: Passo a passo detalhado
- **Mitigation**: Como corrigir/prevenir
- **Evidence**: O que documentar
- **References**: Links OWASP, CVE, artigos

### **4. Exportar Relatório**
- Clique em **📄 Exportar PDF**
- Use Ctrl+P (ou Cmd+P) e "Salvar como PDF"
- Relatório inclui: métricas, status, notas, evidências

### **5. Filtros e Organização**
- Filtre por: **Status**, **Tester**, **Fase do Workflow**
- Pesquise por palavra-chave
- Visualize progresso em tempo real

---

## 📚 Documentação Técnica Incluída

### **Guias de Validação de Dados por Linguagem**

| Linguagem | Arquivo | Conteúdo |
|-----------|---------|----------|
| **JavaScript/TypeScript** | `DATA-VALIDATION-JAVASCRIPT.md` | Zod, Joi, DOMPurify, SQL prepared statements |
| **Python** | `DATA-VALIDATION-PYTHON.md` | Pydantic, Marshmallow, bleach, SQLAlchemy |
| **PHP** | `DATA-VALIDATION-PHP.md` | filter_var, HTMLPurifier, PDO, Symfony Validator |
| **Java** | `DATA-VALIDATION-JAVA.md` | Jakarta Validation, OWASP Java HTML Sanitizer, PreparedStatement |
| **C#/.NET** | `DATA-VALIDATION-DOTNET.md` | Data Annotations, FluentValidation, AntiXSS, Entity Framework |

### **Guias de Ferramentas e Práticas**

| Guia | Arquivo | Conteúdo |
|------|---------|----------|
| **SAST** | `SAST-TOOLS-GUIDE.md` | Ferramentas SAST, integração CI/CD, checklist |
| **DAST** | `DAST-PRACTICAL-GUIDE.md` | Burp, ZAP, Nuclei, testes dinâmicos |
| **API Security** | `API-SECURITY-GUIDE.md` | REST, GraphQL, autenticação, rate limiting |
| **LLM Security** | `OWASP-LLM-TOP-10-COMPLETO.md` | Prompt injection, data poisoning, model DoS |
| **CSPM** | `CSPM-PRACTICAL-GUIDE.md` | Cloud Security Posture Management |
| **DevSecOps** | `DEVSECOPS-AUTOMATION-GUIDE.md` | Automação de segurança em pipelines |

---

## 🎓 Para Quem é Este Projeto?

### **👨‍💻 Desenvolvedores**
- Aprender secure coding practices
- Validar segurança de aplicações
- Preparar-se para code reviews de segurança

### **🔒 Analistas de Segurança**
- Conduzir pentests estruturados
- Documentar findings com evidências
- Gerar relatórios profissionais

### **🎯 Bug Bounty Hunters**
- Checklist de vulnerabilidades para testar
- Comandos e payloads prontos
- Metodologia OWASP atualizada

### **📚 Estudantes**
- Aprender Application Security do zero
- Guias didáticos com exemplos
- Referências para aprofundamento

### **🏢 Empresas**
- Padronizar auditorias de segurança
- Treinar equipes em AppSec
- Compliance (ISO 27001, PCI-DSS, LGPD)

---

## 🏗️ Arquitetura do Projeto

```
Owasp_Checklist_testing/
├── 📱 FRONTEND
│   ├── index.html           # Layout principal
│   ├── styles.css           # Dark theme profissional
│   └── app.mjs              # Lógica de interface
│
├── 🗄️ BACKEND
│   ├── server.mjs           # Express + LowDB
│   └── state.json           # Persistência local
│
├── 📊 MÓDULOS DE CHECKLIST
│   ├── data.mjs             # OWASP Web, PTES, SAST/DAST
│   ├── apiSecurity.mjs      # 🆕 OWASP API Top 10 2023
│   ├── mobileSecurity.mjs   # 🆕 MASVS/MASTG
│   ├── threatModeling.mjs   # 🆕 STRIDE, PASTA, LINDDUN
│   ├── businessLogic.mjs    # 🆕 Business Logic Flaws
│   ├── supplyChainSecurity.mjs # 🆕 SCA, SBOM
│   ├── loggingMonitoring.mjs   # 🆕 Logging, SIEM, IR
│   ├── cloudSecurity.mjs    # Cloud (AWS, Azure, GCP)
│   ├── secureCodeChecklist.mjs
│   ├── serverConfig.mjs
│   └── owaspCheatSheetChecklist.mjs
│
├── 📖 DOCUMENTAÇÃO
│   ├── README.md            # Este arquivo
│   ├── CHECKLIST-COMPLETO.md
│   ├── API-SECURITY-GUIDE.md
│   ├── SAST-TOOLS-GUIDE.md
│   ├── DAST-PRACTICAL-GUIDE.md
│   ├── DEVSECOPS-AUTOMATION-GUIDE.md
│   ├── OWASP-LLM-TOP-10-COMPLETO.md
│   ├── CSPM-PRACTICAL-GUIDE.md
│   ├── DATA-VALIDATION-*.md (5 linguagens)
│   └── NOTAS-TECNICAS.md
│
├── 🧪 TESTES
│   ├── src/logic.test.js
│   └── src/security-validation.test.js
│
└── ⚙️ BUILD & CONFIG
    ├── package.json
    ├── build.mjs            # esbuild
    └── dist/                # Build output
```

---

## 🏗️ Project Architecture

```
owasp-checklist/
├── apps/web/
│   ├── app/
│   │   ├── (auth)/sign-in/page.tsx
│   │   ├── dashboard/page.tsx
│   │   ├── projects/[id]/page.tsx
│   │   ├── checklists/page.tsx
│   │   ├── findings/[id]/page.tsx
│   │   ├── exports/print/[assessmentId]/page.tsx
│   │   ├── api/v1/{auth,projects,assessments,findings,exports}/
│   │   └── layout.tsx
│   ├── components/{ui,charts,forms}/
│   ├── lib/
│   │   ├── auth.ts (NextAuth config)
│   │   ├── prisma.ts (DB client)
│   │   ├── rbac.ts (Role-based access control)
│   │   ├── rate-limit.ts (Rate limiting)
│   │   ├── validation/
│   │   ├── api-response.ts
│   │   └── logger.ts (Pino)
│   ├── e2e/tests.spec.ts (Playwright)
│   └── package.json
├── packages/
│   ├── content/
│   │   ├── checklists/*.yaml
│   │   └── references/
│   └── cli/bin/owaspctl.ts
├── prisma/
│   ├── schema.prisma
│   └── seeds/seed.ts
├── docker/
│   ├── Dockerfile.web
│   └── docker-compose.yml
└── package.json (workspace root)
```

## 🛠️ Tech Stack

### **Frontend**
- **Next.js 14+** - React with App Router
- **TailwindCSS** - Utility-first CSS
- **Radix UI** - Accessible components
- **React Hook Form + Zod** - Form validation

### **Backend**
- **Node.js 20+** - Runtime
- **Next.js API Routes** - REST endpoints
- **Prisma ORM** - Type-safe database
- **Zod** - Schema validation
- **NextAuth.js v5** - Authentication + JWT

### **Database**
- **SQLite** - Local development (file-based)
- **Postgres** - Production ready (just change `DATABASE_URL`)

### **Security**
- **bcryptjs** - Password hashing
- **Helmet** - HTTP security headers
- **express-rate-limit** - Rate limiting
- **rehype-sanitize** - HTML sanitization
- **CSP Headers** - XSS protection

### **Exports**
- **Playwright** - PDF generation
- **Custom CSV/JSON** - Data serialization

### **Testing**
- **Vitest** - Unit tests
- **Playwright** - E2E tests

### **DevOps**
- **Docker** - Containerization
- **Docker Compose** - Orchestration
- **pnpm** - Fast package manager

---

## 📊 Estatísticas do Projeto

| Métrica | Valor |
|---------|-------|
| **Módulos de segurança** | 13 |
| **Items de checklist** | 300+ |
| **Guias técnicos** | 300+ |
| **Documentos markdown** | 20+ |
| **Linhas de código** | 10,000+ |
| **Testes automatizados** | 25+ |
| **Comandos práticos** | 500+ |

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Para contribuir:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/NovaFuncionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/NovaFuncionalidade`)
5. Abra um Pull Request

### **Áreas para Contribuição**

- 🌍 Tradução para outros idiomas
- 📱 Novos módulos (IoT Security, Blockchain, etc)
- 🎨 Modo claro (light theme)
- 📊 Mais visualizações de métricas
- 🧪 Labs práticos interativos
- 🤖 Integração com ferramentas (SAST/DAST)

---

## 📜 Licença

Este projeto é licenciado sob a licença ISC.

---

## 🙏 Agradecimentos

- **OWASP Foundation** - pelos frameworks e checklists
- **Comunidade de AppSec** - por compartilhar conhecimento
- **Contribuidores** - por melhorias e feedback

---

## 📞 Suporte

- 🐛 **Issues**: [GitHub Issues](https://github.com/GhostN3xus/Owasp_Checklist_testing/issues)
- 📧 **Email**: (adicione seu email aqui)
- 💬 **Discussões**: [GitHub Discussions](https://github.com/GhostN3xus/Owasp_Checklist_testing/discussions)

---

## 🔗 Links Úteis

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

<div align="center">

**⭐ Se este projeto foi útil, considere dar uma estrela!**

**Feito com ❤️ para a comunidade de Application Security**

[![GitHub stars](https://img.shields.io/github/stars/GhostN3xus/Owasp_Checklist_testing?style=social)](https://github.com/GhostN3xus/Owasp_Checklist_testing)
[![GitHub forks](https://img.shields.io/github/forks/GhostN3xus/Owasp_Checklist_testing?style=social)](https://github.com/GhostN3xus/Owasp_Checklist_testing)

</div>
