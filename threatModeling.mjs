/**
 * Threat Modeling & Secure Design
 * Metodologias: STRIDE, PASTA, LINDDUN, Attack Trees
 * Checklist para design seguro e modelagem de ameaças em early-stage
 */

export const threatModelingChecklist = {
  id: "threat-modeling",
  name: "Threat Modeling",
  description: "Modelagem de Ameaças e Design Seguro - STRIDE, PASTA, LINDDUN, Attack Trees e práticas de Security by Design desde a concepção do produto.",
  sections: [
    {
      id: "tm-fundamentals",
      title: "Fundamentos de Threat Modeling",
      summary: "Princípios básicos, identificação de ativos, stakeholders e boundaries do sistema.",
      items: [
        {
          id: "tm-fund-1",
          title: "Identificar e documentar ativos críticos do sistema",
          description: "Mapear dados, funcionalidades e recursos que precisam de proteção (Crown Jewels).",
          guide: {
            overview: "Threat modeling começa identificando O QUE proteger: dados sensíveis, funcionalidades críticas, recursos valiosos.",
            impact: "Sem identificação de ativos, proteções são genéricas e ineficazes. Foco errado desperdiça recursos.",
            detection: [
              "Mapear fluxos de dados: quais dados são processados/armazenados?",
              "Identificar PII, PHI, PCI, propriedade intelectual",
              "Listar funcionalidades críticas: pagamentos, autenticação, admin",
              "Perguntar: O que um atacante ganharia comprometendo X?"
            ],
            tools: ["Miro", "Lucidchart", "Draw.io", "Microsoft Threat Modeling Tool", "Planilhas"],
            commands: [
              "# Não aplicável (processo manual/colaborativo)",
              "# Ferramentas visuais para criar inventário de ativos"
            ],
            steps: [
              "1. Reunir stakeholders: dev, product, security, compliance",
              "2. Listar todos dados processados: login, transações, mensagens, etc",
              "3. Classificar por sensibilidade: Público / Interno / Confidencial / Crítico",
              "4. Identificar 'Crown Jewels': top 5 ativos mais valiosos",
              "5. Mapear onde ativos estão: banco, cache, logs, backups, terceiros",
              "6. Documentar: Nome do Ativo, Classificação, Localização, Owner",
              "7. Priorizar proteção baseado em valor + risco"
            ],
            mitigation: [
              "Criar Asset Inventory: tabela com todos ativos sensíveis",
              "Aplicar data classification policy",
              "Implementar DLP (Data Loss Prevention) para ativos críticos",
              "Estabelecer data retention policy",
              "Revisar inventário trimestralmente (novos ativos?)"
            ],
            evidence: [
              "Planilha de Asset Inventory com 20+ ativos mapeados",
              "Diagrama mostrando fluxo de dados sensíveis",
              "Classificação de dados aplicada: Confidencial, PII, etc",
              "Crown Jewels identificados: API keys, user credentials, payment data"
            ],
            references: [
              "https://owasp.org/www-community/Threat_Modeling",
              "https://shostack.org/resources/threat-modeling",
              "https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling",
              "NIST SP 800-154 - Guide to Data-Centric System Threat Modeling"
            ]
          }
        },
        {
          id: "tm-fund-2",
          title: "Criar Data Flow Diagram (DFD) do sistema",
          description: "Desenhar diagrama de fluxo de dados mostrando processos, datastores, external entities e trust boundaries.",
          guide: {
            overview: "DFD visualiza arquitetura do sistema, facilitando identificação de ameaças em cada componente e fronteira.",
            impact: "Sem DFD, threat modeling é superficial. DFD revela pontos cegos e attack surfaces ocultos.",
            detection: [
              "Identificar: Processos (círculos), Data Stores (linhas paralelas), External Entities (quadrados), Data Flows (setas)",
              "Marcar trust boundaries (ex: internet → firewall → app → database)",
              "Validar DFD com equipe: cobre toda arquitetura?"
            ],
            tools: ["Microsoft Threat Modeling Tool", "OWASP Threat Dragon", "Lucidchart", "Draw.io"],
            commands: [
              "# Não aplicável (ferramentas visuais)",
              "# Microsoft TMT gera DFD automaticamente",
              "# OWASP Threat Dragon: https://threatdragon.com"
            ],
            steps: [
              "1. Escolher ferramenta de diagramação",
              "2. Identificar external entities: User, Admin, Third-party API",
              "3. Mapear processos: Login Service, Payment Processor, Email Sender",
              "4. Mapear data stores: User DB, Session Cache, Log Files",
              "5. Desenhar data flows: User → Login → DB, Payment → Stripe API",
              "6. Marcar trust boundaries: Public Internet | DMZ | Internal Network | Database",
              "7. Validar DFD: cobre todos componentes? fluxos corretos?"
            ],
            mitigation: [
              "Manter DFD atualizado em cada release",
              "Usar DFD como base para STRIDE/PASTA analysis",
              "Revisar DFD em design reviews",
              "Versionar DFD no repositório (docs/architecture/)"
            ],
            evidence: [
              "DFD Level 0 (contexto geral do sistema)",
              "DFD Level 1 (decomposição de subsistemas)",
              "Trust boundaries claramente marcadas",
              "Screenshot do DFD no Threat Dragon"
            ],
            references: [
              "https://owasp.org/www-community/Threat_Modeling_Process#data-flow-diagrams",
              "https://www.microsoft.com/en-us/securityengineering/sdl/threatmodeling",
              "https://threatdragon.com/"
            ]
          }
        }
      ]
    },
    {
      id: "stride",
      title: "STRIDE Threat Modeling",
      summary: "Análise sistemática de ameaças: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.",
      items: [
        {
          id: "stride-1",
          title: "Identificar ameaças de Spoofing (falsificação de identidade)",
          description: "Analisar onde atacante pode se passar por usuário legítimo, sistema ou entidade.",
          guide: {
            overview: "Spoofing: atacante se passa por outro usuário/sistema. Afeta autenticação e identidade.",
            impact: "Acesso não autorizado, ações realizadas em nome de terceiros, bypass de controles de acesso.",
            detection: [
              "Revisar DFD: onde há autenticação?",
              "Perguntar: Atacante pode fingir ser Admin? Outro usuário? Servidor legítimo?",
              "Verificar: tokens, sessions, certificates, API keys"
            ],
            tools: ["Microsoft TMT (gera ameaças STRIDE automaticamente)", "Planilha de ameaças"],
            commands: [
              "# Exemplos de ameaças Spoofing:",
              "# - Roubo de session token",
              "# - Falsificação de JWT",
              "# - Man-in-the-Middle com certificado falso",
              "# - IP spoofing",
              "# - Email spoofing (phishing)"
            ],
            steps: [
              "1. Para cada processo no DFD, perguntar: 'Como sei que a entidade é quem diz ser?'",
              "2. Listar pontos de autenticação: login, API calls, service-to-service",
              "3. Identificar ameaças: session hijacking, JWT forgery, CSRF",
              "4. Avaliar controles existentes: MFA? TLS? Token validation?",
              "5. Documentar gaps: onde autenticação é fraca?",
              "6. Propor mitigações: implementar MFA, certificate pinning, etc"
            ],
            mitigation: [
              "Implementar autenticação forte: MFA, certificados mTLS",
              "Validar JWTs adequadamente (signature, exp, iss)",
              "Usar HTTPS com certificate pinning",
              "Implementar CSRF tokens",
              "Validar sender de emails (SPF, DKIM, DMARC)",
              "Logs de autenticação para detecção de anomalias"
            ],
            evidence: [
              "Lista de ameaças Spoofing identificadas: 8 cenários",
              "Mitigações propostas: MFA em /admin, JWT com exp curto",
              "DFD anotado com pontos de autenticação",
              "Tabela: Ameaça | Probabilidade | Impacto | Mitigação"
            ],
            references: [
              "https://owasp.org/www-community/Threat_Modeling_Process#stride",
              "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats#spoofing"
            ]
          }
        },
        {
          id: "stride-2",
          title: "Identificar ameaças de Tampering (modificação não autorizada)",
          description: "Analisar onde atacante pode alterar dados em trânsito, em repouso ou código.",
          guide: {
            overview: "Tampering: atacante modifica dados, configurações ou código sem autorização.",
            impact: "Corrupção de dados, injeção de código malicioso, alteração de logs, bypass de validações.",
            detection: [
              "Revisar data stores e data flows no DFD",
              "Perguntar: Onde dados podem ser modificados? Há validação de integridade?",
              "Verificar: databases, files, logs, messages, parameters"
            ],
            tools: ["HMAC/Digital Signatures", "File Integrity Monitoring (AIDE, Tripwire)"],
            commands: [
              "# Exemplos de ameaças Tampering:",
              "# - SQL Injection (modificar queries)",
              "# - Parameter tampering (alterar price=100 para price=1)",
              "# - Log tampering (deletar evidências)",
              "# - Code injection (XSS, RCE)",
              "# - Man-in-the-Middle (alterar payload em trânsito)"
            ],
            steps: [
              "1. Para cada data store: 'Pode ser modificado indevidamente?'",
              "2. Para cada data flow: 'Pode ser interceptado e alterado?'",
              "3. Identificar ameaças: SQLi, parameter tampering, code injection",
              "4. Avaliar controles: prepared statements? HTTPS? input validation?",
              "5. Documentar gaps: logs sem proteção de integridade?",
              "6. Propor mitigações: HMAC em logs, input validation, WAF"
            ],
            mitigation: [
              "Usar prepared statements (prevenir SQLi)",
              "Validar input server-side (whitelist)",
              "HTTPS para proteger dados em trânsito",
              "HMAC ou digital signatures em dados críticos",
              "File Integrity Monitoring para detectar alterações",
              "Logs append-only e tamper-evident (WORM storage)",
              "Code signing para prevenir tampering de binários"
            ],
            evidence: [
              "Lista de ameaças Tampering: 12 cenários",
              "Mitigações: prepared statements em 100% queries, HMAC em logs",
              "Gap identificado: uploads sem validação de conteúdo",
              "Proposta: implementar antivirus scan em uploads"
            ],
            references: [
              "https://owasp.org/www-community/Threat_Modeling_Process#stride",
              "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats#tampering"
            ]
          }
        },
        {
          id: "stride-3",
          title: "Identificar ameaças de Repudiation (não-repúdio)",
          description: "Analisar onde usuário pode negar ter realizado ação crítica.",
          guide: {
            overview: "Repudiation: falta de auditoria permite usuário negar ações (ex: 'não fui eu que transferiu dinheiro').",
            impact: "Impossibilidade de provar quem fez o quê, disputas não resolvíveis, fraudes não detectáveis.",
            detection: [
              "Identificar ações críticas: transações, alterações de config, acessos admin",
              "Perguntar: Há log dessa ação? Log é imutável? Contém who/what/when?"
            ],
            tools: ["SIEM", "Audit logs", "Digital signatures", "Blockchain (tamper-evident)"],
            commands: [
              "# Exemplos de ameaças Repudiation:",
              "# - Usuário nega ter feito transação (sem log)",
              "# - Admin nega ter deletado dados (logs podem ser alterados)",
              "# - Ausência de timestamp/assinatura em ações críticas"
            ],
            steps: [
              "1. Listar ações críticas que requerem non-repudiation",
              "2. Verificar se há logging adequado: user_id, timestamp, action, IP",
              "3. Avaliar integridade dos logs: podem ser alterados?",
              "4. Identificar gaps: ações sem log, logs não protegidos",
              "5. Propor mitigações: logs centralizados, SIEM, digital signatures"
            ],
            mitigation: [
              "Implementar audit logging completo: who, what, when, where, how",
              "Logs imutáveis: append-only, WORM storage, blockchain",
              "Centralizar logs em SIEM (dificulta tampering local)",
              "Digital signatures em transações críticas",
              "Timestamping com trusted time source (NTP)",
              "Retention policy: manter logs por período legal (5+ anos)"
            ],
            evidence: [
              "Lista de ações críticas sem logging adequado",
              "Proposta: implementar audit trail para payments, config changes",
              "Gap: logs de admin actions podem ser deletados localmente",
              "Mitigação: centralizar logs em SIEM com retenção 7 anos"
            ],
            references: [
              "https://owasp.org/www-community/Threat_Modeling_Process#stride",
              "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats#repudiation"
            ]
          }
        },
        {
          id: "stride-4",
          title: "Identificar ameaças de Information Disclosure (vazamento de dados)",
          description: "Analisar onde dados sensíveis podem ser expostos indevidamente.",
          guide: {
            overview: "Information Disclosure: exposição de dados confidenciais via vazamentos, acessos não autorizados, debug info.",
            impact: "Vazamento de PII, credenciais, segredos, propriedade intelectual, violação de compliance.",
            detection: [
              "Revisar data stores: dados sensíveis criptografados?",
              "Revisar data flows: trafegam por canais seguros?",
              "Verificar: logs com senhas? stack traces em produção? backups desprotegidos?"
            ],
            tools: ["SAST", "Secret scanning (GitGuardian, TruffleHog)", "DLP"],
            commands: [
              "# Exemplos de ameaças Information Disclosure:",
              "# - Logs contendo passwords, tokens",
              "# - Stack traces em responses de erro",
              "# - Backups sem criptografia",
              "# - API retornando dados excessivos (over-fetching)",
              "# - Secrets em código/config (hardcoded)"
            ],
            steps: [
              "1. Para cada data store sensível: 'Está criptografado? Access control?'",
              "2. Revisar logs: contém dados sensíveis?",
              "3. Verificar error handling: expõe stack traces?",
              "4. Analisar APIs: retornam mais dados que necessário?",
              "5. Scan de secrets: git history, env vars, config files",
              "6. Propor mitigações: encryption at rest, redact logs, DLP"
            ],
            mitigation: [
              "Criptografar dados sensíveis at rest (AES-256) e in transit (TLS 1.3)",
              "Redact dados sensíveis de logs: mascarar CPF, cartões, senhas",
              "Error handling: nunca expor stack traces em produção",
              "APIs: retornar apenas dados necessários (DTO/serializers)",
              "Secret management: usar Vault, AWS Secrets Manager",
              "DLP (Data Loss Prevention) para monitorar exfiltração",
              "Implementar data classification e access controls"
            ],
            evidence: [
              "Lista de 15 ameaças de Information Disclosure",
              "Gap crítico: logs contendo passwords em plain text",
              "API retornando 25 campos quando apenas 5 são necessários",
              "Proposta: implementar log scrubbing, DTOs em APIs"
            ],
            references: [
              "https://owasp.org/www-community/Threat_Modeling_Process#stride",
              "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats#information-disclosure"
            ]
          }
        },
        {
          id: "stride-5",
          title: "Identificar ameaças de Denial of Service (negação de serviço)",
          description: "Analisar onde atacante pode esgotar recursos ou tornar sistema indisponível.",
          guide: {
            overview: "DoS: atacante consome recursos (CPU, memória, banda, conexões) tornando sistema inacessível.",
            impact: "Downtime, perda de receita, SLA breach, reputação danificada.",
            detection: [
              "Identificar recursos limitados: CPU, RAM, disk, DB connections, bandwidth",
              "Perguntar: O que acontece se receber 1M requests/segundo?",
              "Verificar: rate limiting? pagination? resource quotas?"
            ],
            tools: ["Load testing (k6, JMeter)", "DDoS protection (Cloudflare, AWS Shield)"],
            commands: [
              "# Exemplos de ameaças DoS:",
              "# - Flood de requests sem rate limiting",
              "# - Regex DoS (ReDoS) com patterns maliciosos",
              "# - Queries pesadas sem timeout",
              "# - Upload de arquivos gigantes",
              "# - Zip bomb, XML bomb"
            ],
            steps: [
              "1. Para cada processo: 'Pode consumir recursos ilimitados?'",
              "2. Identificar endpoints sem rate limiting",
              "3. Verificar queries SQL: há timeout? limite de rows?",
              "4. Analisar uploads: limite de tamanho?",
              "5. Testar ReDoS em regex patterns",
              "6. Propor mitigações: rate limiting, CDN, auto-scaling"
            ],
            mitigation: [
              "Implementar rate limiting: 100 req/min por IP/user",
              "Pagination obrigatória: max 100 items por página",
              "Database query timeout: 30 segundos",
              "Limite de tamanho de upload: 10MB",
              "Usar CDN para absorver DDoS (Cloudflare)",
              "Auto-scaling para lidar com picos de tráfego",
              "Implementar circuit breaker para serviços downstream",
              "Validar regex para prevenir ReDoS"
            ],
            evidence: [
              "Lista de 10 ameaças DoS identificadas",
              "Gap crítico: endpoint /search sem rate limiting",
              "Query SELECT * FROM logs (sem LIMIT) pode travar DB",
              "Proposta: rate limiting em /search, LIMIT 1000 em queries"
            ],
            references: [
              "https://owasp.org/www-community/Threat_Modeling_Process#stride",
              "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats#denial-of-service",
              "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
            ]
          }
        },
        {
          id: "stride-6",
          title: "Identificar ameaças de Elevation of Privilege (escalação de privilégios)",
          description: "Analisar onde usuário comum pode obter privilégios admin/elevados.",
          guide: {
            overview: "Elevation of Privilege: atacante obtém permissões além das autorizadas (user → admin).",
            impact: "Acesso total ao sistema, alteração de configurações críticas, comprometimento completo.",
            detection: [
              "Revisar pontos de autorização: APIs, UIs, funções",
              "Perguntar: Usuário pode acessar função admin? Modificar seu próprio role?",
              "Verificar: role checks? IDOR? mass assignment de isAdmin?"
            ],
            tools: ["Burp Suite (test authorization)", "SAST tools"],
            commands: [
              "# Exemplos de ameaças Elevation of Privilege:",
              "# - Mass assignment: {\"isAdmin\": true}",
              "# - IDOR para acessar /admin/users",
              "# - SQL Injection para modificar role no DB",
              "# - Path traversal para acessar arquivos de config",
              "# - Deserialization vulnerabilities (RCE)"
            ],
            steps: [
              "1. Para cada função privilegiada: 'Há validação de role?'",
              "2. Testar IDOR em endpoints admin",
              "3. Verificar mass assignment em updates de perfil",
              "4. Analisar SQL queries: validam ownership/role?",
              "5. Testar path traversal, LFI, deserialization",
              "6. Propor mitigações: RBAC rigoroso, input validation"
            ],
            mitigation: [
              "Implementar RBAC (Role-Based Access Control) robusto",
              "Validar role em CADA endpoint: if (user.role !== 'admin') return 403",
              "Usar frameworks de autorização: Casbin, CASL",
              "Prevenir mass assignment: whitelist de campos permitidos",
              "Prepared statements para prevenir SQLi",
              "Input validation para prevenir path traversal",
              "Desabilitar deserialization de dados não confiáveis",
              "Testes automatizados de autorização"
            ],
            evidence: [
              "Lista de 8 ameaças de Elevation of Privilege",
              "Gap crítico: endpoint PUT /users/:id sem validação de role",
              "Mass assignment permite: {\"role\": \"admin\"}",
              "Proposta: RBAC middleware, DTO com whitelist de campos"
            ],
            references: [
              "https://owasp.org/www-community/Threat_Modeling_Process#stride",
              "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats#elevation-of-privilege",
              "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
            ]
          }
        }
      ]
    },
    {
      id: "pasta",
      title: "PASTA (Process for Attack Simulation and Threat Analysis)",
      summary: "Metodologia risk-centric em 7 estágios focada em simulação de ataques e análise de risco.",
      items: [
        {
          id: "pasta-1",
          title: "Stage 1-3: Definir objetivos, boundaries técnicos e decompor aplicação",
          description: "Estabelecer escopo, identificar componentes, mapear arquitetura técnica.",
          guide: {
            overview: "PASTA foca em análise de risco alinhada ao negócio. Estágios iniciais definem CONTEXTO do sistema.",
            impact: "Contexto claro permite priorização de ameaças baseada em impacto real ao negócio.",
            detection: [
              "Stage 1: Definir objetivos (compliance? redução de risco? novo produto?)",
              "Stage 2: Definir scope técnico (componentes in-scope vs out-of-scope)",
              "Stage 3: Decompor aplicação (arquitetura, tecnologias, dependências)"
            ],
            tools: ["Architecture diagrams", "Component diagrams", "C4 model"],
            commands: [
              "# Não aplicável - processo de documentação",
              "# Deliverable: Architecture diagram, Component list, Tech stack"
            ],
            steps: [
              "Stage 1 - Definir Objetivos:",
              "1. Por que fazer threat model? (compliance, nova feature, vulnerabilidade?)",
              "2. Quais objetivos de segurança? (confidencialidade, integridade, disponibilidade)",
              "3. Quais requisitos de compliance? (PCI-DSS, HIPAA, LGPD)",
              "",
              "Stage 2 - Definir Technical Scope:",
              "4. Quais componentes estão in-scope?",
              "5. Quais tecnologias: languages, frameworks, cloud services",
              "6. Definir boundaries: o que está fora do controle?",
              "",
              "Stage 3 - Application Decomposition:",
              "7. Criar diagrama de arquitetura (frontend, backend, database, APIs)",
              "8. Listar dependências: libraries, third-party services",
              "9. Mapear entry points e trust boundaries"
            ],
            mitigation: [
              "Documentar decisões de arquitetura (ADRs)",
              "Manter diagrama atualizado",
              "Revisar tech stack periodicamente para deprecated/vulnerable components"
            ],
            evidence: [
              "Documento de objetivos do threat model",
              "Lista de componentes in-scope: 15 microservices",
              "Architecture diagram C4 Level 2",
              "Tech stack: Node.js, PostgreSQL, Redis, AWS S3, Stripe API"
            ],
            references: [
              "https://versprite.com/blog/what-is-pasta-threat-modeling/",
              "https://owasp.org/www-pdf-archive/AppSecEU2012_PASTA.pdf"
            ]
          }
        },
        {
          id: "pasta-2",
          title: "Stage 4-5: Analisar ameaças e vulnerabilidades",
          description: "Threat intelligence, análise de attack vectors, mapeamento de vulnerabilidades conhecidas.",
          guide: {
            overview: "Stages 4-5: Combinar threat intelligence com análise de vulnerabilidades específicas da stack.",
            impact: "Foco em ameaças REAIS e RELEVANTES (não genéricas), priorizando atacantes ativos no setor.",
            detection: [
              "Stage 4: Threat Analysis - quem são atacantes? motivações? TTPs?",
              "Stage 5: Vulnerability Analysis - quais CVEs afetam nossa stack? OWASP Top 10?"
            ],
            tools: ["MITRE ATT&CK", "CVE databases", "NIST NVD", "Exploit-DB", "Threat intel feeds"],
            commands: [
              "# Pesquisar CVEs para tecnologias em uso",
              "# Exemplo: Node.js vulnerabilities",
              "curl 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=node.js'",
              "",
              "# Verificar dependências vulneráveis",
              "npm audit",
              "snyk test"
            ],
            steps: [
              "Stage 4 - Threat Analysis:",
              "1. Identificar threat actors: script kiddies, hacktivists, APTs, insiders",
              "2. Motivação: financial gain, espionage, disruption",
              "3. TTPs (Tactics, Techniques, Procedures): phishing, SQLi, ransomware",
              "4. Consultar MITRE ATT&CK para técnicas relevantes ao setor",
              "",
              "Stage 5 - Vulnerability Analysis:",
              "5. Listar tecnologias em uso: frameworks, libraries, services",
              "6. Pesquisar CVEs conhecidos (NVD, Snyk, GitHub Advisories)",
              "7. Verificar OWASP Top 10 aplicável ao tipo de app",
              "8. Fazer scan de dependências: npm audit, OWASP Dependency-Check",
              "9. Mapear vulnerabilidades a componentes do Stage 3"
            ],
            mitigation: [
              "Manter stack atualizado (patch management)",
              "Assinar feeds de threat intelligence do setor",
              "Implementar vulnerability management program",
              "Usar SCA (Software Composition Analysis) automatizado"
            ],
            evidence: [
              "Lista de threat actors relevantes: Cybercrime groups targeting fintech",
              "MITRE ATT&CK techniques mapeadas: T1190 (Exploit Public-Facing Application)",
              "CVEs identificados: CVE-2024-XXXX afetando Express.js",
              "npm audit output: 12 vulnerabilidades (3 high, 9 moderate)"
            ],
            references: [
              "https://attack.mitre.org/",
              "https://nvd.nist.gov/",
              "https://versprite.com/blog/what-is-pasta-threat-modeling/"
            ]
          }
        },
        {
          id: "pasta-3",
          title: "Stage 6-7: Modelar ataques e analisar riscos/contramedidas",
          description: "Simular attack scenarios, calcular risco, priorizar mitigações.",
          guide: {
            overview: "Stages finais: Simular ataques realísticos, quantificar risco (likelihood x impact), priorizar fixes.",
            impact: "Priorização baseada em risco real permite alocar recursos de forma eficiente.",
            detection: [
              "Stage 6: Attack Modeling - como atacante exploraria vulnerabilidades?",
              "Stage 7: Risk Analysis - qual probabilidade? impacto? custo de mitigação?"
            ],
            tools: ["Attack trees", "Risk matrix", "CVSS calculator"],
            commands: [
              "# Não aplicável - análise qualitativa/quantitativa",
              "# Deliverable: Attack scenarios, Risk matrix, Remediation plan"
            ],
            steps: [
              "Stage 6 - Attack Modeling:",
              "1. Para cada vulnerabilidade, criar attack scenario: como explorar?",
              "2. Desenhar attack tree: passos necessários para exploração",
              "3. Identificar pre-conditions: acesso? credentials? ferramentas?",
              "4. Simular ataque: PoC ou walkthrough teórico",
              "",
              "Stage 7 - Risk & Impact Analysis:",
              "5. Para cada ataque, calcular Likelihood (Low/Med/High)",
              "6. Calcular Impact (Low/Med/High/Critical)",
              "7. Risk = Likelihood x Impact (usar matriz de risco)",
              "8. Priorizar: High risk → immediate fix, Low risk → backlog",
              "9. Propor contramedidas: preventive, detective, corrective",
              "10. Calcular ROI de cada mitigação (custo vs redução de risco)"
            ],
            mitigation: [
              "Implementar mitigações de alto risco PRIMEIRO",
              "Aceitar riscos baixos com justificativa formal (risk acceptance)",
              "Implementar defense in depth (múltiplas camadas)",
              "Monitorar riscos residuais após mitigação"
            ],
            evidence: [
              "Attack tree: SQLi → Data Exfiltration → Sell on Dark Web",
              "Risk matrix: 5 High risks, 12 Medium, 8 Low",
              "Priorização: Fix SQLi (High risk) antes de UI cosmetic issue (Low)",
              "Remediation plan: 3 sprints para mitigar todos High risks"
            ],
            references: [
              "https://versprite.com/blog/what-is-pasta-threat-modeling/",
              "https://owasp.org/www-community/Threat_Modeling_Process"
            ]
          }
        }
      ]
    },
    {
      id: "linddun",
      title: "LINDDUN (Privacy Threat Modeling)",
      summary: "Threat modeling focado em privacidade: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance.",
      items: [
        {
          id: "linddun-1",
          title: "Analisar ameaças de Linkability (vinculação de dados)",
          description: "Verificar se dados de usuário podem ser linkados entre contextos diferentes.",
          guide: {
            overview: "Linkability: capacidade de vincular ações/dados de um usuário em diferentes contextos (ex: correlacionar browsing history com compras).",
            impact: "Perfil detalhado do usuário, re-identificação anônima, violação de privacidade (LGPD/GDPR).",
            detection: [
              "Identificar persistent identifiers: user_id, device_id, cookies",
              "Verificar: dados de diferentes fontes podem ser correlacionados?",
              "Testar: logs de diferentes serviços compartilham IDs?"
            ],
            tools: ["Privacy audit", "Data flow analysis", "GDPR compliance tools"],
            commands: [
              "# Não aplicável - análise de dados e flows",
              "# Verificar: user_id em logs de analytics + payment + support → linkável"
            ],
            steps: [
              "1. Mapear todos identificadores persistentes no sistema",
              "2. Analisar data flows: dados cruzam boundaries com mesmo ID?",
              "3. Verificar third-party tracking: pixels, analytics, ads",
              "4. Testar: possível correlacionar ações de usuário entre serviços?",
              "5. Avaliar risk: impacto de linkability à privacidade",
              "6. Propor mitigações: pseudonymization, data minimization"
            ],
            mitigation: [
              "Usar identificadores diferentes por contexto (pseudonymization)",
              "Implementar data minimization: coletar apenas necessário",
              "Anonymization de logs: remover/hash PII",
              "Limitar compartilhamento de dados com third-parties",
              "Privacy-preserving analytics (differential privacy)",
              "Compliance: GDPR Article 25 (Privacy by Design)"
            ],
            evidence: [
              "Mapeamento: user_id usado em 8 sistemas diferentes",
              "Gap: analytics third-party recebe full user profile",
              "Proposta: usar hashed IDs para analytics, pseudonymize logs"
            ],
            references: [
              "https://www.linddun.org/",
              "https://www.linddun.org/linddun-go",
              "GDPR Article 25 - Data Protection by Design"
            ]
          }
        },
        {
          id: "linddun-2",
          title: "Verificar compliance com regulações de privacidade (LGPD/GDPR)",
          description: "Validar se sistema atende requisitos de consentimento, direitos dos titulares, DPO, etc.",
          guide: {
            overview: "Non-compliance: falha em atender LGPD/GDPR pode resultar em multas de até 4% do faturamento global.",
            impact: "Multas milionárias, danos à reputação, processos judiciais.",
            detection: [
              "Verificar: há consent management? direito ao esquecimento? portabilidade?",
              "Validar: DPO nomeado? DPIA realizada? registro de processamento?",
              "Testar: usuário consegue exportar/deletar seus dados?"
            ],
            tools: ["OneTrust", "TrustArc", "GDPR compliance checklists"],
            commands: [
              "# Não aplicável - auditoria de compliance",
              "# Checklist GDPR: 99 requisitos a validar"
            ],
            steps: [
              "1. Lawful basis: consentimento? legitimate interest? contract?",
              "2. Consent management: opt-in claro? granular? withdraw fácil?",
              "3. Direitos dos titulares: access, rectification, erasure, portability",
              "4. Data Protection Impact Assessment (DPIA) para high-risk processing",
              "5. DPO nomeado e contactável?",
              "6. Registro de atividades de processamento",
              "7. Data breach notification process (72h)",
              "8. Privacy Policy clara e acessível",
              "9. Vendor management: DPAs com third-parties?",
              "10. International transfers: adequacy decision ou safeguards?"
            ],
            mitigation: [
              "Implementar consent management platform",
              "Criar endpoints: /api/user/export, /api/user/delete",
              "Realizar DPIA para novos processamentos",
              "Nomear DPO e publicar contato",
              "Treinar equipe em privacy awareness",
              "Manter registro atualizado de processamentos",
              "Estabelecer incident response plan para breaches",
              "Revisar contratos com vendors (DPA clauses)"
            ],
            evidence: [
              "Gap: ausência de consent management (cookies sem opt-in)",
              "Gap: função 'deletar conta' não remove dados de backups",
              "Gap: DPIA não realizada para novo feature de geolocation",
              "Proposta: implementar CMP, DPIA template, DPO nomeado"
            ],
            references: [
              "https://www.linddun.org/",
              "https://gdpr.eu/",
              "https://www.gov.br/cidadania/pt-br/acesso-a-informacao/lgpd",
              "https://ico.org.uk/for-organisations/guide-to-data-protection/"
            ]
          }
        }
      ]
    },
    {
      id: "attack-trees",
      title: "Attack Trees & Kill Chain Analysis",
      summary: "Modelagem visual de caminhos de ataque e análise de cyber kill chain.",
      items: [
        {
          id: "attack-tree-1",
          title: "Construir Attack Tree para cenário crítico",
          description: "Criar árvore de ataque mostrando goal do atacante e passos necessários (AND/OR nodes).",
          guide: {
            overview: "Attack Tree: representação hierárquica de como atacante pode alcançar objetivo (root node).",
            impact: "Visualização clara de attack paths, identificação de pontos de mitigação mais eficazes.",
            detection: [
              "Definir goal: 'Exfiltrar dados de clientes'",
              "Decompor em sub-goals: acesso ao DB, bypass de encryption, exfiltração",
              "Identificar passos: SQLi OR credential stuffing → dump database → decrypt → upload to C2"
            ],
            tools: ["AttackTree+ (software)", "Draw.io", "Lucidchart", "Paper/whiteboard"],
            commands: [
              "# Exemplo de Attack Tree (texto):",
              "Goal: Exfiltrate customer data",
              "├─ AND",
              "│  ├─ Gain database access",
              "│  │  ├─ OR",
              "│  │  │  ├─ SQL Injection",
              "│  │  │  ├─ Stolen credentials (phishing)",
              "│  │  │  └─ Exploit DB vulnerability (CVE-XXXX)",
              "│  │  └─ OR",
              "│  │     ├─ Bypass firewall",
              "│  │     └─ Internal access (insider)",
              "│  ├─ Extract data",
              "│  │  ├─ Dump database (mysqldump)",
              "│  │  └─ Decrypt if encrypted",
              "│  └─ Exfiltrate",
              "│     ├─ DNS tunneling",
              "│     ├─ HTTPS upload to C2",
              "│     └─ Physical exfiltration (USB)"
            ],
            steps: [
              "1. Definir goal do atacante (root node): 'Steal API keys'",
              "2. Perguntar: 'Como atacante pode alcançar isso?'",
              "3. Decompor em sub-goals (child nodes)",
              "4. Identificar AND nodes: todos passos necessários",
              "5. Identificar OR nodes: alternativas (qualquer uma funciona)",
              "6. Adicionar leaf nodes: ações atômicas (SQLi, phishing)",
              "7. Calcular probability de sucesso em cada node",
              "8. Identificar choke points: mitigar nodes críticos"
            ],
            mitigation: [
              "Identificar single points of failure (SPOFs) na árvore",
              "Mitigar nodes com maior impact ou facilidade de exploração",
              "Implementar defense in depth: múltiplas camadas dificultam AND paths",
              "Monitorar para detectar partial completion de attack paths"
            ],
            evidence: [
              "Attack tree diagram para 'Compromise admin account'",
              "Identificados 3 OR paths: phishing, credential reuse, brute-force",
              "Choke point: MFA bloqueia todos 3 paths",
              "Recomendação: implementar MFA (mitigação de alto impacto)"
            ],
            references: [
              "https://www.schneier.com/academic/archives/1999/12/attack_trees.html",
              "https://owasp.org/www-community/Threat_Modeling_Process#attack-trees"
            ]
          }
        }
      ]
    }
  ]
};
